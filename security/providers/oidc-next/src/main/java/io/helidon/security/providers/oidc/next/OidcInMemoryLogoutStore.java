/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.security.providers.oidc.next;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;

/**
 * Process-local back-channel logout state. Restarting forgets revocations but does not invalidate unexpired protected
 * browser cookies. This intentionally does not preserve the logout guarantee across process restarts or replicas.
 */
final class OidcInMemoryLogoutStore implements OidcBackChannelLogoutStore {
    private static final String INITIAL_GENERATION = "initial";
    private static final String VOLATILE_INCARNATION = "in-memory";
    private static final int DEFAULT_MAX_ENTRIES = 100_000;

    private final ReentrantLock lock = new ReentrantLock();
    private final Map<SubjectKey, SubjectState> subjects = new HashMap<>();
    private final Map<SidKey, SidState> sessions = new HashMap<>();
    private final Map<JtiKey, RecordedEvent> jwtIds = new HashMap<>();
    private final Clock clock;
    private final int maxEntries;

    private Instant nextCleanup = Instant.EPOCH;
    private boolean unhealthy;

    OidcInMemoryLogoutStore() {
        this(Clock.systemUTC(), DEFAULT_MAX_ENTRIES);
    }

    OidcInMemoryLogoutStore(Clock clock, int maxEntries) {
        this.clock = Objects.requireNonNull(clock);
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("Logout store capacity must be positive");
        }
        this.maxEntries = maxEntries;
    }

    @Override
    public Marker beginSession(Identity identity) {
        Instant now = clock.instant();
        lock.lock();
        try {
            requireHealthy();
            pruneIfNeeded(now);
            SubjectState state = subjects.get(subjectKey(identity));
            if (state != null && identity.expiresAt().isAfter(state.expiresAt())) {
                subjects.put(subjectKey(identity),
                             new SubjectState(state.generation(), identity.expiresAt(), state.revokedBefore()));
            }
            return new Marker(VOLATILE_INCARNATION, state == null ? INITIAL_GENERATION : state.generation());
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean revoked(Session session) {
        lock.lock();
        try {
            requireHealthy();
            pruneIfNeeded(clock.instant());
            Identity identity = session.identity();
            if (identity.sid().map(sid -> sessions.get(new SidKey(identity.tenantId(), identity.issuer(), sid)))
                    .filter(state -> state.subject() == null || state.subject().equals(identity.subject()))
                    .isPresent()) {
                return true;
            }
            SubjectState state = subjects.get(subjectKey(identity));
            if (state == null) {
                // The process-local store forgot its old subject generations on restart. Accept cookies from an
                // earlier incarnation when there is no currently recorded logout for this subject.
                return false;
            }
            // A new subject-wide logout must invalidate even a cookie issued before this process was started.
            return !state.generation().equals(session.marker().subjectGeneration())
                    || !identity.originalIssuedAt().isAfter(state.revokedBefore());
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void revoke(LogoutEvent event, Instant retainUntil) {
        Objects.requireNonNull(retainUntil);
        Instant now = clock.instant();
        lock.lock();
        try {
            requireHealthy();
            pruneIfNeeded(now);
            JtiKey jwtId = new JtiKey(event.tenantId(), event.issuer(), event.jwtId());
            RecordedEvent previousEvent = jwtIds.get(jwtId);
            if (previousEvent != null) {
                // Back-channel delivery may be retried. Advancing a subject generation twice would log out a new login.
                if (previousEvent.event().equals(event)) {
                    return;
                }
                throw new IllegalArgumentException("OP reused a Logout Token ID for a different event");
            }
            SidKey sid = event.sid().map(value -> new SidKey(event.tenantId(), event.issuer(), value)).orElse(null);
            SubjectKey subject = event.subject().map(value -> new SubjectKey(event.tenantId(), event.issuer(), value))
                    .orElse(null);
            int added = 1 + (sid != null && !sessions.containsKey(sid) ? 1 : 0)
                    + (sid == null && !subjects.containsKey(subject) ? 1 : 0);
            if ((long) subjects.size() + sessions.size() + jwtIds.size() + added > maxEntries) {
                // No live revocation may be evicted to make room. Refuse subsequent authentication until restart.
                unhealthy = true;
                throw new IllegalStateException("OIDC back-channel logout store capacity is exhausted");
            }
            if (sid != null) {
                SidState previous = sessions.get(sid);
                if (previous != null && previous.subject() != null && subject != null
                        && !previous.subject().equals(subject.subject())) {
                    throw new IllegalArgumentException("OP session ID is associated with a different subject");
                }
                String boundSubject = subject == null || previous != null && previous.subject() == null
                        ? null : subject.subject();
                sessions.put(sid, new SidState(boundSubject,
                                               previous == null ? retainUntil : latest(retainUntil, previous.expiresAt())));
            } else {
                SubjectState previous = subjects.get(subject);
                subjects.put(subject,
                             new SubjectState(UUID.randomUUID().toString(),
                                              previous == null ? retainUntil : latest(retainUntil, previous.expiresAt()),
                                              previous == null ? event.issuedAt()
                                                      : latest(event.issuedAt(), previous.revokedBefore())));
            }
            jwtIds.put(jwtId, new RecordedEvent(event, latest(retainUntil, event.expiresAt())));
        } finally {
            lock.unlock();
        }
    }

    private SubjectKey subjectKey(Identity identity) {
        return new SubjectKey(identity.tenantId(), identity.issuer(), identity.subject());
    }

    private Instant latest(Instant first, Instant second) {
        return first.isAfter(second) ? first : second;
    }

    private void pruneIfNeeded(Instant now) {
        if (now.isBefore(nextCleanup)
                && (long) subjects.size() + sessions.size() + jwtIds.size() < maxEntries) {
            return;
        }
        subjects.values().removeIf(state -> !state.expiresAt().isAfter(now));
        sessions.values().removeIf(state -> !state.expiresAt().isAfter(now));
        jwtIds.values().removeIf(event -> !event.expiresAt().isAfter(now));
        nextCleanup = OidcTokenLifetime.expiresAt(now, 30);
    }

    private void requireHealthy() {
        if (unhealthy) {
            throw new IllegalStateException("OIDC back-channel logout store cannot answer revocation queries");
        }
    }

    private record SubjectKey(String tenantId, String issuer, String subject) {
    }

    private record SidKey(String tenantId, String issuer, String sid) {
    }

    private record JtiKey(String tenantId, String issuer, String jwtId) {
    }

    private record SubjectState(String generation, Instant expiresAt, Instant revokedBefore) {
    }

    private record SidState(String subject, Instant expiresAt) {
    }

    private record RecordedEvent(LogoutEvent event, Instant expiresAt) {
    }
}
