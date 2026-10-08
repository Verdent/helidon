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

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.http.DateTime;
import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.HttpMediaTypes;
import io.helidon.http.Status;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcJwkSetHttpCacheTest {
    private static final Instant START = Instant.parse("2026-10-08T12:00:00Z");
    private static final String ORIGINAL = Resource.create("oidc-next-verify-public-jwk.json").string();
    private static final String ROTATED = Resource.create("oidc-next-sign-public-jwk.json").string();
    @TempDir
    private Path tempDir;

    @Test
    void defaultRemoteAgeLimitRemovesDecommissionedKeys() {
        MutableClock clock = new MutableClock();
        try (Peer peer = new Peer(clock, OidcJwkSetConfig.create())) {
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            peer.respond(ROTATED, Map.of());

            clock.advance(Duration.ofMinutes(5).minusSeconds(1));
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(1));

            clock.advance(Duration.ofSeconds(1));
            JwkKeys updated = peer.manager.jwkKeys();
            assertThat(updated.forKeyId("verify-rsa").isEmpty(), is(true));
            assertThat(updated.forKeyId("sign-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(2));
            assertThat(peer.lastRequestCacheControl.get(), is("no-cache"));
        }
    }

    @Test
    void providerMaxAgeUsesTheShorterOfHttpFreshnessAndConfiguredMaximum() {
        MutableClock clock = new MutableClock();
        Map<HeaderName, String> headers = Map.of(HeaderNames.CACHE_CONTROL, "public, max-age=120",
                                                  HeaderNames.AGE, "90",
                                                  HeaderNames.DATE, httpDate(START.minusSeconds(100)));
        try (Peer peer = new Peer(clock, OidcJwkSetConfig.create())) {
            peer.respond(ORIGINAL, headers);
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            peer.respond(ROTATED, headers);

            clock.advance(Duration.ofSeconds(19));
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(1));
            clock.advance(Duration.ofSeconds(1));
            assertThat(peer.manager.jwkKeys().forKeyId("sign-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(2));
        }
    }

    @Test
    void anAlreadyExpiredResponseCannotReviveAnOldKey() {
        MutableClock clock = new MutableClock();
        try (Peer peer = new Peer(clock, OidcJwkSetConfig.create())) {
            peer.respond(ORIGINAL, Map.of(HeaderNames.CACHE_CONTROL, "max-age=30", HeaderNames.AGE, "360"));
            assertThrows(OidcJwkSetManager.UnavailableException.class, peer.manager::jwkKeys);

            peer.respond(ROTATED, Map.of());
            clock.advance(Duration.ofSeconds(10));
            assertThat(peer.manager.jwkKeys().forKeyId("sign-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(2));
        }
    }

    @Test
    void anOldIntermediaryResponseCannotResetTheLocalMaximumAge() {
        MutableClock clock = new MutableClock();
        try (Peer peer = new Peer(clock, OidcJwkSetConfig.create())) {
            // Without a provider lifetime, the five-minute fallback still includes time spent in intermediary caches.
            peer.respond(ORIGINAL, Map.of(HeaderNames.AGE, "360"));
            assertThrows(OidcJwkSetManager.UnavailableException.class, peer.manager::jwkKeys);

            peer.respond(ROTATED, Map.of());
            clock.advance(Duration.ofSeconds(10));
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isEmpty(), is(true));
            assertThat(peer.manager.jwkKeys().forKeyId("sign-rsa").isPresent(), is(true));
        }
    }

    @Test
    void localVerificationKeysAreNotAgeRefreshedByTheRemoteDefault() throws Exception {
        MutableClock clock = new MutableClock();
        Path localKeys = tempDir.resolve("verification-jwks.json");
        Files.writeString(localKeys, ORIGINAL);
        OidcJwkSetManager manager = OidcJwkSetManager.createLocal("local",
                ResourceConfig.builder().path(localKeys).buildPrototype(), clock, OidcJwkSetConfig.create());

        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
        Files.writeString(localKeys, ROTATED);
        clock.advance(Duration.ofDays(1));
        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
        assertThat(manager.jwkKeys().forKeyId("sign-rsa").isEmpty(), is(true));
    }

    @Test
    void expiresAppliesOnlyWhenMaxAgeIsAbsent() {
        MutableClock clock = new MutableClock();
        try (Peer peer = new Peer(clock, OidcJwkSetConfig.create())) {
            peer.respond(ORIGINAL, Map.of(HeaderNames.EXPIRES, httpDate(START.plusSeconds(30))));
            peer.manager.jwkKeys();
            peer.respond(ROTATED, Map.of());

            clock.advance(Duration.ofSeconds(29));
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            clock.advance(Duration.ofSeconds(1));
            assertThat(peer.manager.jwkKeys().forKeyId("sign-rsa").isPresent(), is(true));

            peer.respond(ORIGINAL, Map.of(HeaderNames.CACHE_CONTROL, "max-age=60", HeaderNames.EXPIRES, "0"));
            clock.advance(Duration.ofMinutes(5));
            peer.manager.jwkKeys();
            peer.respond(ROTATED, Map.of());
            clock.advance(Duration.ofSeconds(30));
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            clock.advance(Duration.ofSeconds(30));
            assertThat(peer.manager.jwkKeys().forKeyId("sign-rsa").isPresent(), is(true));
        }
    }

    @Test
    void invalidExpiresDoesNotAllowCaching() {
        MutableClock clock = new MutableClock();
        try (Peer peer = new Peer(clock, OidcJwkSetConfig.create())) {
            peer.respond(ORIGINAL, Map.of(HeaderNames.EXPIRES, "0"));
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            peer.respond(ROTATED, Map.of());
            assertThat(peer.manager.jwkKeys().forKeyId("sign-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(2));
        }
    }

    @Test
    void noCacheRevalidatesEachUseAndNeverServesStaleOnError() {
        MutableClock clock = new MutableClock();
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .maxStaleOnError(Duration.ofMinutes(5)).buildPrototype();
        try (Peer peer = new Peer(clock, config)) {
            peer.respond(ORIGINAL, Map.of(HeaderNames.CACHE_CONTROL, "no-cache, max-age=3600"));
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            peer.respond(ROTATED, Map.of(HeaderNames.CACHE_CONTROL, "no-cache"));
            assertThat(peer.manager.jwkKeys().forKeyId("sign-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(2));

            peer.fail(Status.INTERNAL_SERVER_ERROR_500);
            assertThrows(OidcJwkSetManager.UnavailableException.class, peer.manager::jwkKeys);
            assertThat(peer.requests.get(), is(3));
        }
    }

    @Test
    void noStoreNeverReusesAResponseEvenWithStaleGrace() {
        MutableClock clock = new MutableClock();
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .maxStaleOnError(Duration.ofMinutes(5)).buildPrototype();
        try (Peer peer = new Peer(clock, config)) {
            peer.respond(ORIGINAL, Map.of(HeaderNames.CACHE_CONTROL, "no-store"));
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            peer.respond(ROTATED, Map.of(HeaderNames.CACHE_CONTROL, "no-store"));
            assertThat(peer.manager.jwkKeys().forKeyId("sign-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(2));

            peer.fail(Status.INTERNAL_SERVER_ERROR_500);
            assertThrows(OidcJwkSetManager.UnavailableException.class, peer.manager::jwkKeys);
            assertThat(peer.requests.get(), is(3));
        }
    }

    @Test
    void noStoreConcurrentVirtualThreadsDoNotShareStoredKeys() throws Exception {
        MutableClock clock = new MutableClock();
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .admissionTimeout(Duration.ofSeconds(10)).buildPrototype();
        try (Peer peer = new Peer(clock, config);
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            peer.respond(ORIGINAL, Map.of(HeaderNames.CACHE_CONTROL, "no-store"));
            CountDownLatch start = new CountDownLatch(1);
            List<Future<JwkKeys>> callers = IntStream.range(0, 16)
                    .mapToObj(_ -> executor.submit(() -> {
                        if (!start.await(5, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Test callers did not start");
                        }
                        return peer.manager.jwkKeys();
                    }))
                    .toList();
            start.countDown();
            for (Future<JwkKeys> caller : callers) {
                assertThat(caller.get(10, TimeUnit.SECONDS).forKeyId("verify-rsa").isPresent(), is(true));
            }
            assertThat(peer.requests.get(), is(16));
        }
    }

    @Test
    void mustRevalidateDisallowsConfiguredStaleGrace() {
        MutableClock clock = new MutableClock();
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .maxStaleOnError(Duration.ofMinutes(5)).buildPrototype();
        try (Peer peer = new Peer(clock, config)) {
            peer.respond(ORIGINAL, Map.of(HeaderNames.CACHE_CONTROL, "max-age=10, must-revalidate"));
            peer.manager.jwkKeys();
            peer.fail(Status.INTERNAL_SERVER_ERROR_500);

            clock.advance(Duration.ofSeconds(10));
            assertThrows(OidcJwkSetManager.UnavailableException.class, peer.manager::jwkKeys);
            assertThat(peer.requests.get(), is(2));
        }
    }

    @Test
    void providerStaleIfErrorLimitsAnExplicitLocalGracePeriod() {
        MutableClock clock = new MutableClock();
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .maxStaleOnError(Duration.ofSeconds(30)).buildPrototype();
        try (Peer peer = new Peer(clock, config)) {
            peer.respond(ORIGINAL, Map.of(HeaderNames.CACHE_CONTROL, "max-age=10, stale-if-error=5"));
            JwkKeys original = peer.manager.jwkKeys();
            peer.fail(Status.INTERNAL_SERVER_ERROR_500);

            clock.advance(Duration.ofSeconds(10));
            assertThat(peer.manager.jwkKeys(), sameInstance(original));
            clock.advance(Duration.ofSeconds(4));
            assertThat(peer.manager.jwkKeys(), sameInstance(original));
            clock.advance(Duration.ofSeconds(1));
            assertThrows(OidcJwkSetManager.UnavailableException.class, peer.manager::jwkKeys);
            assertThat(peer.requests.get(), is(2));
        }
    }

    @Test
    void failedUnknownKeyRefreshDoesNotInvalidateStillFreshKnownKeys() {
        MutableClock clock = new MutableClock();
        try (Peer peer = new Peer(clock, OidcJwkSetConfig.create())) {
            JwkKeys original = peer.manager.jwkKeys();
            peer.fail(Status.INTERNAL_SERVER_ERROR_500);

            assertThrows(OidcJwkSetManager.UnavailableException.class,
                         () -> peer.manager.jwkKeys(Optional.of("rotated-rsa")));
            assertThat(peer.manager.jwkKeys(Optional.of("verify-rsa")), sameInstance(original));
            assertThat(peer.requests.get(), is(2));
        }
    }

    @Test
    void firstLoadFailureIsUnavailableAndCanRetryAfterTheConfiguredDelay() {
        MutableClock clock = new MutableClock();
        try (Peer peer = new Peer(clock, OidcJwkSetConfig.create())) {
            peer.fail(Status.INTERNAL_SERVER_ERROR_500);
            OidcJwkSetManager.UnavailableException failure =
                    assertThrows(OidcJwkSetManager.UnavailableException.class, peer.manager::jwkKeys);
            assertThat(assertThrows(OidcJwkSetManager.UnavailableException.class, peer.manager::jwkKeys),
                       sameInstance(failure));
            assertThat(peer.requests.get(), is(1));

            peer.respond(ORIGINAL, Map.of());
            clock.advance(Duration.ofSeconds(10));
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(2));
        }
    }

    private static String httpDate(Instant instant) {
        return DateTime.RFC_1123_DATE_TIME.format(instant.atZone(ZoneOffset.UTC));
    }

    private record Reply(String keys, Map<HeaderName, String> headers, Status status) {
    }

    private static final class Peer implements AutoCloseable {
        private final AtomicInteger requests = new AtomicInteger();
        private final AtomicReference<String> lastRequestCacheControl = new AtomicReference<>("");
        private final AtomicReference<Reply> reply = new AtomicReference<>(new Reply(ORIGINAL, Map.of(), Status.OK_200));
        private final WebServer server;
        private final WebClient client;
        private final OidcJwkSetManager manager;

        private Peer(MutableClock clock, OidcJwkSetConfig config) {
            server = WebServer.builder().port(0).routing(routing -> routing.get("/jwks", (request, response) -> {
                requests.incrementAndGet();
                lastRequestCacheControl.set(request.headers().first(HeaderNames.CACHE_CONTROL).orElse(""));
                Reply current = reply.get();
                if (current.status() != Status.OK_200) {
                    response.status(current.status()).send();
                    return;
                }
                response.headers().contentType(HttpMediaTypes.JSON);
                if (!current.headers().containsKey(HeaderNames.DATE)) {
                    response.header(HeaderValues.create(HeaderNames.DATE, httpDate(clock.instant())));
                }
                current.headers().forEach((name, value) -> response.header(HeaderValues.create(name, value)));
                response.send(current.keys());
            })).build().start();
            client = WebClient.builder().shareConnectionCache(false).readTimeout(Duration.ofSeconds(3)).build();
            OidcTenantConfig tenant = OidcTenantConfig.builder().issuer("https://issuer.example")
                    .endpoints(endpoints -> endpoints.tlsRequired(false)
                            .jwksUri(URI.create("http://localhost:" + server.port() + "/jwks")))
                    .buildPrototype();
            manager = OidcJwkSetManager.create("tenant", OidcProviderMetadata.fromStaticConfig(tenant), client,
                                               clock, config);
        }

        private void respond(String keys, Map<HeaderName, String> headers) {
            reply.set(new Reply(keys, headers, Status.OK_200));
        }

        private void fail(Status status) {
            reply.set(new Reply("", Map.of(), status));
        }

        @Override
        public void close() {
            try {
                client.closeResource();
            } finally {
                server.stop();
            }
        }
    }

    private static final class MutableClock extends Clock {
        private final ZoneId zone;
        private Instant now;

        private MutableClock() {
            this(START, ZoneOffset.UTC);
        }

        private MutableClock(Instant now, ZoneId zone) {
            this.now = now;
            this.zone = zone;
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(now, zone);
        }

        @Override
        public Instant instant() {
            return now;
        }

        private void advance(Duration duration) {
            now = now.plus(duration);
        }
    }
}
