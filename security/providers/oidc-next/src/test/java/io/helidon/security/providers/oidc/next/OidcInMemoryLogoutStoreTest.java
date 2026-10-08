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
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcInMemoryLogoutStoreTest {
    private static final String ISSUER = "https://issuer.example";
    private static final Instant NOW = Instant.parse("2026-10-08T10:00:00Z");

    @Test
    void sessionLogoutTargetsSidWithinItsTenant() {
        OidcInMemoryLogoutStore store = store(100);
        OidcBackChannelLogoutStore.Session target = session(store, "default", "alice", "session-a", NOW.minusSeconds(30));
        OidcBackChannelLogoutStore.Session otherSid = session(store, "default", "alice", "session-b", NOW.minusSeconds(30));
        OidcBackChannelLogoutStore.Session otherTenant = session(store, "other", "alice", "session-a", NOW.minusSeconds(30));

        store.revoke(event("default", "alice", "session-a", "event-a"), NOW.plusSeconds(3600));

        assertThat(store.revoked(target), is(true));
        assertThat(store.revoked(otherSid), is(false));
        assertThat(store.revoked(otherTenant), is(false));
        assertThat(store.revoked(session(store, "default", "alice", "session-a", NOW.plusSeconds(1))), is(true));
    }

    @Test
    void subjectLogoutDoesNotRejectNewLoginOrAdvanceTwiceForDuplicateDelivery() {
        OidcInMemoryLogoutStore store = store(100);
        OidcBackChannelLogoutStore.Session oldOne = session(store, "default", "alice", "session-a", NOW.minusSeconds(30));
        OidcBackChannelLogoutStore.Session oldTwo = session(store, "default", "alice", "session-b", NOW.minusSeconds(30));
        OidcBackChannelLogoutStore.Session bob = session(store, "default", "bob", null, NOW.minusSeconds(30));
        OidcBackChannelLogoutStore.LogoutEvent event = event("default", "alice", null, "event-a");

        store.revoke(event, NOW.plusSeconds(3600));

        assertThat(store.revoked(oldOne), is(true));
        assertThat(store.revoked(oldTwo), is(true));
        assertThat(store.revoked(bob), is(false));
        OidcBackChannelLogoutStore.Session fresh = session(store, "default", "alice", "session-new", NOW.plusSeconds(1));
        assertThat(store.revoked(fresh), is(false));
        OidcBackChannelLogoutStore.Session staleCallback =
                session(store, "default", "alice", "session-late", NOW.minusSeconds(30));
        assertThat(store.revoked(staleCallback), is(true));

        store.revoke(event, NOW.plusSeconds(3600));
        assertThat(store.revoked(fresh), is(false));
        assertThrows(IllegalArgumentException.class,
                     () -> store.revoke(event("default", "bob", null, "event-a"), NOW.plusSeconds(3600)));
        assertThat(store.revoked(fresh), is(false));
    }

    @Test
    void lateRetryDoesNotRevokeLoginEstablishedAfterFirstDelivery() {
        AtomicReference<Instant> time = new AtomicReference<>(NOW);
        OidcInMemoryLogoutStore store = new OidcInMemoryLogoutStore(new AdjustableClock(time), 100);
        OidcBackChannelLogoutStore.LogoutEvent event = event("default", "alice", null, "late-retry");
        // The handler retains the replay marker through exp and the accepted clock-skew window.
        Instant retainUntil = NOW.plusSeconds(180);
        store.revoke(event, retainUntil);

        time.set(NOW.plusSeconds(150));
        OidcBackChannelLogoutStore.Session fresh = session(store, "default", "alice", "new-op-session",
                                                           NOW.plusSeconds(1));
        assertThat(store.revoked(fresh), is(false));

        store.revoke(event, retainUntil);
        assertThat(store.revoked(fresh), is(false));
    }

    @Test
    void processRestartForgetsRevocationsButAcceptsStillValidCookies() {
        OidcBackChannelLogoutStore first = store(100);
        OidcBackChannelLogoutStore.Session sidTarget = session(first, "default", "alice", "session-a", NOW);
        OidcBackChannelLogoutStore.Session subjectTarget = session(first, "default", "alice", "session-b", NOW);
        first.revoke(event("default", "alice", "session-a", "sid-logout"), NOW.plusSeconds(3600));
        assertThat(first.revoked(sidTarget), is(true));
        assertThat(first.revoked(subjectTarget), is(false));
        first.revoke(event("default", "alice", null, "subject-logout"), NOW.plusSeconds(3600));
        assertThat(first.revoked(subjectTarget), is(true));
        OidcBackChannelLogoutStore.Session fresh = session(first, "default", "alice", "session-new",
                                                           NOW.plusSeconds(1));
        assertThat(first.revoked(fresh), is(false));

        OidcBackChannelLogoutStore second = store(100);
        assertThat(second.revoked(sidTarget), is(false));
        assertThat(second.revoked(subjectTarget), is(false));
        assertThat(second.revoked(fresh), is(false));

        // New notifications must still log out sessions issued before the restart, whatever their OP issue time.
        second.revoke(event("default", "alice", null, "new-subject-logout"), NOW.plusSeconds(3600));
        assertThat(second.revoked(sidTarget), is(true));
        assertThat(second.revoked(subjectTarget), is(true));
        assertThat(second.revoked(fresh), is(true));
    }

    @Test
    void capacityDoesNotSilentlyDiscardARevocation() {
        OidcInMemoryLogoutStore store = store(2);
        OidcBackChannelLogoutStore.Session source = session(store, "default", "alice", "session-a", NOW);
        store.revoke(event("default", "alice", "session-a", "event-a"), NOW.plusSeconds(3600));

        assertThat(store.revoked(source), is(true));
        assertThrows(IllegalStateException.class,
                     () -> store.revoke(event("default", "bob", "session-b", "event-b"), NOW.plusSeconds(3600)));
        assertThrows(IllegalStateException.class, () -> store.revoked(source));
    }

    @Test
    void expiredMarkersArePrunedWithoutAcceptingAnUnexpiredSession() {
        AtomicReference<Instant> time = new AtomicReference<>(NOW);
        OidcInMemoryLogoutStore store = new OidcInMemoryLogoutStore(new AdjustableClock(time), 2);
        store.revoke(event("default", "alice", "session-a", "event-a"), NOW.plusSeconds(5));
        time.set(NOW.plusSeconds(121));
        // A cookie issued before this marker's retention deadline also expired; a new session has a new OP sid.
        store.revoke(event("default", "alice", "session-b", "event-b"), NOW.plusSeconds(3600));
        assertThat(store.revoked(session(store, "default", "alice", "session-b", NOW.plusSeconds(121))), is(true));
    }

    @Test
    void concurrentVirtualThreadRetriesApplyOnlyOneSubjectLogout() throws Exception {
        OidcInMemoryLogoutStore store = store(100);
        OidcBackChannelLogoutStore.Session original = session(store, "default", "alice", "session-a", NOW.minusSeconds(1));
        OidcBackChannelLogoutStore.LogoutEvent notification = event("default", "alice", null, "event-a");
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> submitted = new ArrayList<>();
            for (int index = 0; index < 24; index++) {
                submitted.add(executor.submit(() -> {
                    start.await();
                    store.revoke(notification, NOW.plusSeconds(3600));
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> task : submitted) {
                task.get();
            }
        }
        assertThat(store.revoked(original), is(true));
        assertThat(store.revoked(session(store, "default", "alice", "new-login", NOW.plusSeconds(1))), is(false));
    }

    private static OidcInMemoryLogoutStore store(int capacity) {
        return new OidcInMemoryLogoutStore(Clock.fixed(NOW, ZoneOffset.UTC), capacity);
    }

    private static OidcBackChannelLogoutStore.Session session(OidcBackChannelLogoutStore store,
                                                               String tenant,
                                                               String subject,
                                                               String sid,
                                                               Instant issuedAt) {
        OidcBackChannelLogoutStore.Identity identity = new OidcBackChannelLogoutStore.Identity(
                tenant, ISSUER, subject, Optional.ofNullable(sid), issuedAt, NOW.plusSeconds(3600));
        return new OidcBackChannelLogoutStore.Session(identity, store.beginSession(identity));
    }

    private static OidcBackChannelLogoutStore.LogoutEvent event(String tenant,
                                                                String subject,
                                                                String sid,
                                                                String jwtId) {
        return new OidcBackChannelLogoutStore.LogoutEvent(tenant,
                                                          ISSUER,
                                                          Optional.ofNullable(subject),
                                                          Optional.ofNullable(sid),
                                                          jwtId,
                                                          NOW,
                                                          NOW.plusSeconds(120));
    }

    private static final class AdjustableClock extends Clock {
        private final AtomicReference<Instant> time;

        private AdjustableClock(AtomicReference<Instant> time) {
            this.time = time;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return time.get();
        }
    }
}
