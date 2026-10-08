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

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Stream;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.uri.UriQuery;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HttpMediaTypes;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class OidcJwkSetConcurrencyTest {
    @Test
    void encryptedRequestObjectFailsClosedOnOverloadAndRecovers() throws Exception {
        try (Peer peer = new Peer(config(0, "PT30S"))) {
            peer.body.set(Resource.create("oidc-next-encrypt-public-jwk.json").string());
            OidcTenantConfig tenant = OidcTenantConfig.builder().issuer("https://issuer.example").clientId("client-id")
                    .clientSecret("client-secret")
                    .endpoints(endpoints -> endpoints.authorizationEndpointUri(URI.create("https://issuer.example/authorize"))
                            .tokenEndpointUri(URI.create("https://issuer.example/token"))
                            .jwksUri(peer.manager.jwkSetUri().orElseThrow()).tlsRequired(false))
                    .authorizationCode(code -> code.redirectionEndpointUri(URI.create("https://rp.example/oidc/callback"))
                            .requestObject(request -> request.mode(OidcRequestObjectMode.REQUIRED)
                                    .signingJwk(jwk -> jwk.resourcePath("oidc-next-sign-jwk.json"))
                                    .signingKeyId("sign-rsa").signingAlgorithm("RS256")
                                    .encryptionAlgorithm("RSA-OAEP-256")))
                    .cookies(cookies -> cookies.password("test-cookie-password"))
                    .jwkSet(config(0, "PT30S")).buildPrototype();
            SecurityEnvironment environment = SecurityEnvironment.builder().targetUri(URI.create("https://rp.example/resource"))
                    .path("/resource").transport("https").build();
            try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                                   .putTenant("default", tenant).buildPrototype());
                 var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("default").orElseThrow();
                assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                           context.ready(), is(true));
                Future<?> leader = executor.submit(() -> context.jwkSetManager().jwkKeys());
                try {
                    assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                    AuthenticationResponse rejected = provider.authenticate(OidcProviderTest.request(null, environment));
                    assertThat(rejected.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                    assertThat(rejected.statusCode().orElseThrow(), is(503));
                    assertThat(rejected.responseHeaders().containsKey("Location"), is(false));
                    assertThat(rejected.responseHeaders().containsKey("Set-Cookie"), is(false));
                    peer.release.countDown();
                    leader.get(5, TimeUnit.SECONDS);
                    AuthenticationResponse recovered = provider.authenticate(OidcProviderTest.request(null, environment));
                    assertThat(recovered.statusCode().orElseThrow(), is(303));
                    URI location = URI.create(recovered.responseHeaders().get("Location").getFirst());
                    EncryptedJwt encrypted = EncryptedJwt.parseToken(UriQuery.create(location).get("request"));
                    assertThat(encrypted.headers().algorithm().orElseThrow(), is("RSA-OAEP-256"));
                    JwkKeys decryptionKeys = JwkKeys.builder().resource(Resource.create("oidc-next-encrypt-jwk.json")).build();
                    byte[] payload = encrypted.decryptPayload(decryptionKeys,
                                                              decryptionKeys.forKeyId("encrypt-rsa").orElseThrow());
                    SignedJwt signed = SignedJwt.parseToken(new String(payload, StandardCharsets.UTF_8));
                    signed.verifySignature(JwkKeys.builder().resource(Resource.create("oidc-next-sign-public-jwk.json"))
                                                   .build()).checkValid();
                    assertThat(signed.getJwt().issuer().orElseThrow(), is("client-id"));
                    assertThat(peer.requests.get(), is(1));
                } finally {
                    peer.release.countDown();
                }
            }
        }
    }

    @Test
    void timedOutCallerReleasesItsQueueSlot() throws Exception {
        try (Peer peer = new Peer(config(1, "PT2S"));
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<JwkKeys> leader = executor.submit(() -> peer.manager.jwkKeys());
            try {
                assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                Call timedOut = new Call(peer.manager::jwkKeys);
                timedOut.awaitWaiting();
                assertThat(timedOut.failure(), instanceOf(OidcJwkSetManager.UnavailableException.class));
                assertThat(leader.isDone(), is(false));
                Call replacement = new Call(peer.manager::jwkKeys);
                replacement.awaitWaiting();
                peer.release.countDown();
                assertThat(replacement.result.get(5, TimeUnit.SECONDS), sameInstance(leader.get(5, TimeUnit.SECONDS)));
                assertThat(peer.requests.get(), is(1));
            } finally {
                peer.release.countDown();
            }
        }
    }

    @Test
    void zeroTimeoutAdmitsAnIdleLoaderButDoesNotWaitWhenBusy() throws Exception {
        try (Peer peer = new Peer(config(128, "PT0S"));
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<JwkKeys> leader = executor.submit(() -> peer.manager.jwkKeys());
            try {
                assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                assertThat(new Call(peer.manager::jwkKeys).failure(), instanceOf(OidcJwkSetManager.UnavailableException.class));
                peer.release.countDown();
                JwkKeys keys = leader.get(5, TimeUnit.SECONDS);
                assertThat(peer.manager.jwkKeys(), sameInstance(keys));
            } finally {
                peer.release.countDown();
            }
        }
    }

    @Test
    void localVerificationSourceUsesTheSameBoundedAdmission() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger loads = new AtomicInteger();
        String resourceName = "controlled-verification-jwks";
        ClassLoader original = Thread.currentThread().getContextClassLoader();
        ClassLoader controlled = new ClassLoader(original) {
            @Override
            public InputStream getResourceAsStream(String name) {
                if (!resourceName.equals(name)) {
                    return super.getResourceAsStream(name);
                }
                loads.incrementAndGet();
                entered.countDown();
                try {
                    if (!release.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Test did not release local JWKS");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                }
                return original.getResourceAsStream("oidc-next-verify-public-jwk.json");
            }
        };
        OidcJwkSetManager manager = OidcJwkSetManager.createLocal("tenant",
                ResourceConfig.builder().resourcePath(resourceName).buildPrototype(), Clock.systemUTC(), config(0, "PT30S"));
        Supplier<JwkKeys> lookup = () -> {
            Thread.currentThread().setContextClassLoader(controlled);
            try {
                return manager.jwkKeys();
            } finally {
                Thread.currentThread().setContextClassLoader(original);
            }
        };
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<JwkKeys> leader = executor.submit(lookup::get);
            try {
                assertThat(entered.await(5, TimeUnit.SECONDS), is(true));
                assertThat(new Call(lookup).failure(), instanceOf(OidcJwkSetManager.UnavailableException.class));
                assertThat(loads.get(), is(1));
                release.countDown();
                JwkKeys keys = leader.get(5, TimeUnit.SECONDS);
                assertThat(new Call(lookup).result.get(5, TimeUnit.SECONDS), sameInstance(keys));
                assertThat(loads.get(), is(1));
            } finally {
                release.countDown();
            }
        }
    }

    @Test
    void positiveQueueCapacityAndInterruptedSlotReclamationAreExact() throws Exception {
        try (Peer peer = new Peer(config(1, "PT30S"));
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<JwkKeys> leader = executor.submit(() -> peer.manager.jwkKeys());
            try {
                assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                Call first = new Call(peer.manager::jwkKeys);
                first.awaitWaiting();
                assertThat(new Call(peer.manager::jwkKeys).failure(), instanceOf(OidcJwkSetManager.UnavailableException.class));

                first.thread.interrupt();
                assertThat(first.failure(), instanceOf(OidcJwkSetManager.UnavailableException.class));
                assertThat(first.interrupted.get(), is(true));
                Call replacement = new Call(peer.manager::jwkKeys);
                replacement.awaitWaiting();
                assertThat(new Call(peer.manager::jwkKeys).failure(), instanceOf(OidcJwkSetManager.UnavailableException.class));

                peer.release.countDown();
                JwkKeys keys = leader.get(5, TimeUnit.SECONDS);
                assertThat(replacement.result.get(5, TimeUnit.SECONDS), sameInstance(keys));
                assertThat(peer.manager.jwkKeys(), sameInstance(keys));
                assertThat(peer.requests.get(), is(1));
            } finally {
                peer.release.countDown();
            }
        }
    }

    @Test
    void preInterruptedColdCallerDoesNotStartALoad() throws Exception {
        try (Peer peer = new Peer(config(1, "PT30S"))) {
            Call interrupted = new Call(() -> {
                Thread.currentThread().interrupt();
                return peer.manager.jwkKeys();
            });
            assertThat(interrupted.failure(), instanceOf(OidcJwkSetManager.UnavailableException.class));
            assertThat(interrupted.interrupted.get(), is(true));
            assertThat(peer.requests.get(), is(0));
            peer.release.countDown();
            assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            assertThat(peer.requests.get(), is(1));
        }
    }

    @TestFactory
    Stream<DynamicTest> refreshAdmissionDoesNotTurnOverloadIntoStaleKeyAcceptance() {
        return Stream.of("expired", "unknown").flatMap(mode -> Stream.of(true, false)
                .map(stale -> dynamicTest(mode + "/stale=" + stale, () -> {
                    MutableClock clock = new MutableClock();
                    OidcJwkSetConfig.Builder config = OidcJwkSetConfig.builder()
                            .maxQueued(0).admissionTimeout(Duration.ofSeconds(30))
                            .unknownKeyIdRefreshInterval(Duration.ZERO).staleOnError(stale);
                    if ("expired".equals(mode)) {
                        config.refreshInterval(Duration.ofSeconds(1));
                    }
                    try (Peer peer = new Peer(config.buildPrototype(), clock, 2);
                         var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                        JwkKeys original = peer.manager.jwkKeys();
                        clock.advance(Duration.ofSeconds(2));
                        peer.body.updateAndGet(value -> value.replace("\"verify-rsa\"", "\"rotated-rsa\""));
                        Supplier<JwkKeys> lookup = "expired".equals(mode)
                                ? peer.manager::jwkKeys
                                : () -> peer.manager.jwkKeys(Optional.of("rotated-rsa"));
                        Future<JwkKeys> leader = executor.submit(lookup::get);
                        try {
                            assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                            assertThat(new Call(lookup).failure(), instanceOf(OidcJwkSetManager.UnavailableException.class));
                            if ("unknown".equals(mode)) {
                                assertThat(peer.manager.jwkKeys(Optional.of("verify-rsa")), sameInstance(original));
                            }
                            assertThat(peer.requests.get(), is(2));
                            peer.release.countDown();
                            JwkKeys rotated = leader.get(5, TimeUnit.SECONDS);
                            assertThat(rotated.forKeyId("rotated-rsa").isPresent(), is(true));
                            assertThat(peer.manager.jwkKeys(Optional.of("rotated-rsa")), sameInstance(rotated));
                            assertThat(peer.requests.get(), is(2));
                        } finally {
                            peer.release.countDown();
                        }
                    }
                })));
    }

    @TestFactory
    Stream<DynamicTest> failedRefreshSharesItsOutcomeAndKeepsItsRetryPolicy() {
        return Stream.of(true, false).map(stale -> dynamicTest("stale=" + stale, () -> {
            MutableClock clock = new MutableClock();
            OidcJwkSetConfig config = OidcJwkSetConfig.builder().maxQueued(2)
                    .admissionTimeout(Duration.ofSeconds(30)).refreshInterval(Duration.ofSeconds(1))
                    .failureRetryInterval(Duration.ofSeconds(10)).staleOnError(stale).buildPrototype();
            try (Peer peer = new Peer(config, clock, 2);
                 var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                String goodKeys = peer.body.get();
                JwkKeys original = peer.manager.jwkKeys();
                clock.advance(Duration.ofSeconds(2));
                peer.body.set("not-json");
                Future<JwkKeys> leader = executor.submit(() -> peer.manager.jwkKeys());
                try {
                    assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                    Call first = new Call(peer.manager::jwkKeys);
                    first.awaitWaiting();
                    Call second = new Call(peer.manager::jwkKeys);
                    second.awaitWaiting();
                    assertThat(new Call(peer.manager::jwkKeys).failure(),
                               instanceOf(OidcJwkSetManager.UnavailableException.class));
                    peer.release.countDown();
                    if (stale) {
                        assertThat(leader.get(5, TimeUnit.SECONDS), sameInstance(original));
                        assertThat(first.result.get(5, TimeUnit.SECONDS), sameInstance(original));
                        assertThat(second.result.get(5, TimeUnit.SECONDS), sameInstance(original));
                        assertThat(peer.manager.jwkKeys(), sameInstance(original));
                    } else {
                        Throwable failure = assertThrows(ExecutionException.class,
                                                         () -> leader.get(5, TimeUnit.SECONDS)).getCause();
                        assertThat(first.failure(), sameInstance(failure));
                        assertThat(second.failure(), sameInstance(failure));
                        assertThat(assertThrows(IllegalStateException.class, peer.manager::jwkKeys), sameInstance(failure));
                    }
                    assertThat(peer.requests.get(), is(2));
                    peer.body.set(goodKeys);
                    clock.advance(Duration.ofSeconds(10));
                    assertThat(peer.manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
                    assertThat(peer.requests.get(), is(3));
                } finally {
                    peer.release.countDown();
                }
            }
        }));
    }

    @Test
    void separateManagersDoNotShareAdmissionCapacity() throws Exception {
        try (Peer busy = new Peer(config(0, "PT30S"));
             Peer independent = new Peer(config(0, "PT30S"), Clock.systemUTC(), 0);
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<JwkKeys> leader = executor.submit(() -> busy.manager.jwkKeys());
            try {
                assertThat(busy.entered.await(5, TimeUnit.SECONDS), is(true));
                assertThat(new Call(busy.manager::jwkKeys).failure(), instanceOf(OidcJwkSetManager.UnavailableException.class));
                assertThat(new Call(independent.manager::jwkKeys).result.get(2, TimeUnit.SECONDS)
                                   .forKeyId("verify-rsa").isPresent(), is(true));
                assertThat(leader.isDone(), is(false));
                busy.release.countDown();
                leader.get(5, TimeUnit.SECONDS);
            } finally {
                busy.release.countDown();
            }
        }
    }

    @Test
    void defaultsAndRootNamedConfigurationAreConsistent() {
        OidcJwkSetConfig defaults = OidcJwkSetConfig.create();
        assertThat(defaults.maxQueued(), is(128));
        assertThat(defaults.admissionTimeout(), is(Duration.ofSeconds(1)));
        OidcJwkSetConfig expected = config(7, "PT0.25S");
        OidcProviderConfig root = OidcProviderConfig.create(configuration(
                Map.of("jwk-set.max-queued", "7", "jwk-set.admission-timeout", "PT0.25S")));
        OidcProviderConfig named = OidcProviderConfig.create(configuration(
                Map.of("tenants.tenant.jwk-set.max-queued", "7", "tenants.tenant.jwk-set.admission-timeout", "PT0.25S")));
        assertThat(root.tenants().get("default").jwkSet(), is(expected));
        assertThat(named.tenants().get("tenant").jwkSet(), is(expected));
        assertThat(OidcProviderConfig.builder().jwkSet(expected).buildPrototype().tenants().get("default").jwkSet(),
                   is(expected));
        assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.create(configuration(
                Map.of("jwk-set.max-queued", "7", "tenants.tenant.issuer", "https://issuer.example"))));
    }

    @TestFactory
    Stream<DynamicTest> invalidAdmissionSettingsFailDuringComponentConfiguration() {
        return Stream.of(Map.of("max-queued", "-1"), Map.of("admission-timeout", "PT-1S"))
                .map(values -> dynamicTest(values.toString(), () ->
                        assertThrows(IllegalArgumentException.class, () -> OidcJwkSetConfig.create(configuration(values)))));
    }

    @Test
    void interruptedFollowerFinishesWithoutCancellingTheSharedLoad() throws Exception {
        try (Peer peer = new Peer(config(1, "PT30S"));
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<JwkKeys> leader = executor.submit(() -> peer.manager.jwkKeys());
            Thread follower = null;
            try {
                assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                CountDownLatch entered = new CountDownLatch(1);
                CountDownLatch finished = new CountDownLatch(1);
                AtomicReference<Throwable> failure = new AtomicReference<>();
                AtomicBoolean interrupted = new AtomicBoolean();
                follower = Thread.ofVirtual().start(() -> {
                    entered.countDown();
                    try {
                        peer.manager.jwkKeys();
                    } catch (RuntimeException e) {
                        failure.set(e);
                    } finally {
                        interrupted.set(Thread.currentThread().isInterrupted());
                        finished.countDown();
                    }
                });
                assertThat(entered.await(5, TimeUnit.SECONDS), is(true));
                follower.interrupt();
                assertThat(finished.await(2, TimeUnit.SECONDS), is(true));
                assertThat(failure.get(), instanceOf(IllegalStateException.class));
                assertThat(interrupted.get(), is(true));
                assertThat(leader.isDone(), is(false));

                peer.release.countDown();
                JwkKeys keys = leader.get(5, TimeUnit.SECONDS);
                assertThat(peer.manager.jwkKeys(), sameInstance(keys));
                assertThat(peer.requests.get(), is(1));
            } finally {
                peer.release.countDown();
                if (follower != null) {
                    follower.interrupt();
                    follower.join(Duration.ofSeconds(5));
                }
            }
        }
    }

    @Test
    void callerBeyondQueueCapacityIsRejectedWithoutWaitingForTheLoader() throws Exception {
        try (Peer peer = new Peer(config(0, "PT30S"));
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<JwkKeys> leader = executor.submit(() -> peer.manager.jwkKeys());
            try {
                assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                Future<?> rejected = executor.submit(() -> assertThrows(IllegalStateException.class, peer.manager::jwkKeys));
                rejected.get(2, TimeUnit.SECONDS);
                assertThat(leader.isDone(), is(false));
                peer.release.countDown();
                JwkKeys keys = leader.get(5, TimeUnit.SECONDS);
                assertThat(peer.manager.jwkKeys(), sameInstance(keys));
                assertThat(peer.requests.get(), is(1));
            } finally {
                peer.release.countDown();
            }
        }
    }

    @Test
    void admittedFollowerHasABoundedWaitWithoutPoisoningTheCache() throws Exception {
        try (Peer peer = new Peer(config(1, "PT0.05S"));
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<JwkKeys> leader = executor.submit(() -> peer.manager.jwkKeys());
            try {
                assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                Future<?> rejected = executor.submit(() -> assertThrows(IllegalStateException.class, peer.manager::jwkKeys));
                rejected.get(2, TimeUnit.SECONDS);
                assertThat(leader.isDone(), is(false));
                peer.release.countDown();
                JwkKeys keys = leader.get(5, TimeUnit.SECONDS);
                assertThat(peer.manager.jwkKeys(), sameInstance(keys));
                assertThat(peer.requests.get(), is(1));
            } finally {
                peer.release.countDown();
            }
        }
    }

    private static OidcJwkSetConfig config(int maxQueued, String admissionTimeout) {
        return OidcJwkSetConfig.create(configuration(Map.of("max-queued", Integer.toString(maxQueued),
                                                           "admission-timeout", admissionTimeout)));
    }

    private static Config configuration(Map<String, String> values) {
        return Config.builder()
                .disableEnvironmentVariablesSource().disableSystemPropertiesSource()
                .sources(ConfigSources.create(values)).build();
    }

    private static final class Peer implements AutoCloseable {
        private final AtomicInteger requests = new AtomicInteger();
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicReference<String> body =
                new AtomicReference<>(Resource.create("oidc-next-verify-public-jwk.json").string());
        private final WebServer server;
        private final WebClient client;
        private final OidcJwkSetManager manager;

        private Peer(OidcJwkSetConfig config) {
            this(config, Clock.systemUTC(), 1);
        }

        private Peer(OidcJwkSetConfig config, Clock clock, int blockedRequest) {
            server = WebServer.builder().port(0).routing(routing -> routing.get("/jwks", (_, response) -> {
                if (requests.incrementAndGet() == blockedRequest) {
                    entered.countDown();
                    try {
                        if (!release.await(10, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Test did not release the JWKS response");
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("Test JWKS response was interrupted", e);
                    }
                }
                response.headers().contentType(HttpMediaTypes.JSON);
                response.send(body.get());
            })).build().start();
            client = WebClient.builder().shareConnectionCache(false).readTimeout(Duration.ofSeconds(10)).build();
            OidcTenantConfig tenant = OidcTenantConfig.builder().issuer("https://issuer.example")
                    .endpoints(endpoints -> endpoints.tlsRequired(false)
                            .jwksUri(URI.create("http://localhost:" + server.port() + "/jwks")))
                    .buildPrototype();
            manager = OidcJwkSetManager.create("tenant", OidcProviderMetadata.fromStaticConfig(tenant), client,
                                               clock, config);
        }

        @Override
        public void close() {
            release.countDown();
            try {
                client.closeResource();
            } finally {
                server.stop();
            }
        }
    }

    private static final class Call {
        private final CompletableFuture<JwkKeys> result = new CompletableFuture<>();
        private final AtomicBoolean interrupted = new AtomicBoolean();
        private final Thread thread;

        private Call(Supplier<JwkKeys> action) {
            thread = Thread.ofVirtual().start(() -> {
                JwkKeys keys = null;
                Throwable failure = null;
                try {
                    keys = action.get();
                } catch (Throwable e) {
                    failure = e;
                }
                interrupted.set(Thread.currentThread().isInterrupted());
                if (failure == null) {
                    result.complete(keys);
                } else {
                    result.completeExceptionally(failure);
                }
            });
        }

        private Throwable failure() {
            return assertThrows(ExecutionException.class, () -> result.get(5, TimeUnit.SECONDS)).getCause();
        }

        private void awaitWaiting() throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            // Public thread state is only test coordination; no private manager/limiter fields are inspected.
            while (thread.getState() != Thread.State.WAITING && thread.getState() != Thread.State.TIMED_WAITING
                    && !result.isDone() && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            assertThat(thread.getState(), anyOf(is(Thread.State.WAITING), is(Thread.State.TIMED_WAITING)));
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-09-21T00:00:00Z"));

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return Clock.fixed(now.get(), zone);
        }

        @Override
        public Instant instant() {
            return now.get();
        }

        private void advance(Duration duration) {
            now.updateAndGet(value -> value.plus(duration));
        }
    }
}
