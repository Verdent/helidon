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
        OidcBackChannelLogoutStore.Session target = session(store, "default", "alice", "session-a");
        OidcBackChannelLogoutStore.Session otherSid = session(store, "default", "alice", "session-b");
        OidcBackChannelLogoutStore.Session otherTenant = session(store, "other", "alice", "session-a");

        store.revoke(event("default", "alice", "session-a", "event-a"), NOW.plusSeconds(3600));

        assertThat(store.revoked(target), is(true));
        assertThat(store.revoked(otherSid), is(false));
        assertThat(store.revoked(otherTenant), is(false));
        assertThat(store.revoked(session(store, "default", "alice", "session-a")), is(true));
    }

    @Test
    void subjectLogoutDoesNotRejectNewLoginOrAdvanceTwiceForDuplicateDelivery() {
        OidcInMemoryLogoutStore store = store(100);
        OidcBackChannelLogoutStore.Session oldOne = session(store, "default", "alice", "session-a");
        OidcBackChannelLogoutStore.Session oldTwo = session(store, "default", "alice", "session-b");
        OidcBackChannelLogoutStore.Session bob = session(store, "default", "bob", null);
        OidcBackChannelLogoutStore.LogoutEvent event = event("default", "alice", null, "event-a");
        String inFlight = store.authorizationCheckpoint("default", ISSUER);
        String otherTenantInFlight = store.authorizationCheckpoint("other", ISSUER);

        store.revoke(event, NOW.plusSeconds(3600));

        assertThat(store.revoked(oldOne), is(true));
        assertThat(store.revoked(oldTwo), is(true));
        assertThat(store.revoked(bob), is(false));
        OidcBackChannelLogoutStore.Session fresh = session(store, "default", "alice", "session-new");
        assertThat(store.revoked(fresh), is(false));
        // The callback has not been established yet; its OP ID Token could have the same or a later iat.
        assertThat(store.beginSession(identity("default", "alice", "session-late"), inFlight).isEmpty(), is(true));
        assertThat(store.beginSession(identity("default", "bob", "bob-new"), inFlight).isPresent(), is(true));
        assertThat(store.beginSession(identity("other", "alice", "other-new"), otherTenantInFlight).isPresent(), is(true));

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
        OidcBackChannelLogoutStore.Session fresh = session(store, "default", "alice", "new-op-session");
        assertThat(store.revoked(fresh), is(false));

        store.revoke(event, retainUntil);
        assertThat(store.revoked(fresh), is(false));
    }

    @Test
    void processRestartForgetsRevocationsButAcceptsStillValidCookies() {
        OidcBackChannelLogoutStore first = store(100);
        OidcBackChannelLogoutStore.Session sidTarget = session(first, "default", "alice", "session-a");
        OidcBackChannelLogoutStore.Session subjectTarget = session(first, "default", "alice", "session-b");
        first.revoke(event("default", "alice", "session-a", "sid-logout"), NOW.plusSeconds(3600));
        assertThat(first.revoked(sidTarget), is(true));
        assertThat(first.revoked(subjectTarget), is(false));
        first.revoke(event("default", "alice", null, "subject-logout"), NOW.plusSeconds(3600));
        assertThat(first.revoked(subjectTarget), is(true));
        OidcBackChannelLogoutStore.Session fresh = session(first, "default", "alice", "session-new");
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
        OidcBackChannelLogoutStore.Session source = session(store, "default", "alice", "session-a");
        store.revoke(event("default", "alice", "session-a", "event-a"), NOW.plusSeconds(3600));

        assertThat(store.revoked(source), is(true));
        assertThrows(IllegalStateException.class,
                     () -> store.revoke(event("default", "bob", "session-b", "event-b"), NOW.plusSeconds(3600)));
        assertThrows(IllegalStateException.class, () -> store.revoked(source));
        assertThrows(IllegalStateException.class, () -> store.authorizationCheckpoint("default", ISSUER));
    }

    @Test
    void expiredMarkersArePrunedWithoutAcceptingAnUnexpiredSession() {
        AtomicReference<Instant> time = new AtomicReference<>(NOW);
        OidcInMemoryLogoutStore store = new OidcInMemoryLogoutStore(new AdjustableClock(time), 2);
        store.revoke(event("default", "alice", "session-a", "event-a"), NOW.plusSeconds(5));
        time.set(NOW.plusSeconds(121));
        // A cookie issued before this marker's retention deadline also expired; a new session has a new OP sid.
        store.revoke(event("default", "alice", "session-b", "event-b"), NOW.plusSeconds(3600));
        assertThat(store.revoked(session(store, "default", "alice", "session-b")), is(true));
    }

    @Test
    void concurrentVirtualThreadRetriesApplyOnlyOneSubjectLogout() throws Exception {
        OidcInMemoryLogoutStore store = store(100);
        OidcBackChannelLogoutStore.Session original = session(store, "default", "alice", "session-a");
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
        assertThat(store.revoked(session(store, "default", "alice", "new-login")), is(false));
    }

    @Test
    void concurrentCallbackAndLogoutCannotLeaveASessionAuthenticated() throws Exception {
        for (int attempt = 0; attempt < 32; attempt++) {
            OidcInMemoryLogoutStore store = store(100);
            String pendingRequest = store.authorizationCheckpoint("default", ISSUER);
            OidcBackChannelLogoutStore.Identity identity = identity("default", "alice", "session-a");
            CountDownLatch start = new CountDownLatch(1);
            try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                Future<Optional<OidcBackChannelLogoutStore.Marker>> callback = executor.submit(() -> {
                    start.await();
                    return store.beginSession(identity, pendingRequest);
                });
                Future<?> logout = executor.submit(() -> {
                    start.await();
                    store.revoke(event("default", "alice", null, "event-a"), NOW.plusSeconds(3600));
                    return null;
                });
                start.countDown();
                Optional<OidcBackChannelLogoutStore.Marker> marker = callback.get();
                logout.get();
                marker.ifPresent(value -> assertThat(store.revoked(new OidcBackChannelLogoutStore.Session(identity, value)),
                                                     is(true)));
                assertThat(store.beginSession(identity, pendingRequest).isEmpty(), is(true));
            }
        }
    }

    @Test
    void unknownCheckpointOnlyFailsClosedForSubjectWithKnownLogout() {
        OidcInMemoryLogoutStore first = store(100);
        String checkpoint = first.authorizationCheckpoint("default", ISSUER);
        OidcInMemoryLogoutStore restarted = store(100);

        assertThat(restarted.beginSession(identity("default", "alice", "session-a"), checkpoint).isPresent(), is(true));
        restarted.revoke(event("default", "alice", null, "after-restart"), NOW.plusSeconds(3600));
        assertThat(restarted.beginSession(identity("default", "alice", "session-b"), checkpoint).isEmpty(), is(true));
        assertThat(restarted.beginSession(identity("default", "bob", "session-b"), checkpoint).isPresent(), is(true));
        assertThat(restarted.beginSession(identity("default", "alice", "session-c"), "bad-checkpoint").isEmpty(), is(true));
    }

    private static OidcInMemoryLogoutStore store(int capacity) {
        return new OidcInMemoryLogoutStore(Clock.fixed(NOW, ZoneOffset.UTC), capacity);
    }

    private static OidcBackChannelLogoutStore.Session session(OidcBackChannelLogoutStore store,
                                                               String tenant,
                                                               String subject,
                                                               String sid) {
        OidcBackChannelLogoutStore.Identity identity = identity(tenant, subject, sid);
        return new OidcBackChannelLogoutStore.Session(
                identity, store.beginSession(identity, store.authorizationCheckpoint(tenant, ISSUER)).orElseThrow());
    }

    private static OidcBackChannelLogoutStore.Identity identity(String tenant, String subject, String sid) {
        return new OidcBackChannelLogoutStore.Identity(
                tenant, ISSUER, subject, Optional.ofNullable(sid), NOW.plusSeconds(3600));
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
