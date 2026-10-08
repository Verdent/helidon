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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;

import io.helidon.common.parameters.Parameters;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.SecurityTime;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class OidcClientCredentialsAdmissionTest {
    @Test
    void activeCapacityAndSameKeyFollowersAreBounded() throws Exception {
        try (Peer peer = new Peer(2, 1, "PT30S")) {
            Call first = new Call(() -> peer.request("first"));
            assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
            Call second = new Call(() -> peer.request("second"));
            peer.awaitRequests(2);
            Call follower = new Call(() -> peer.request("first"));
            peer.awaitQueued(1);
            assertFailed(new Call(() -> peer.request("third")).result.get(2, TimeUnit.SECONDS));
            assertFailed(new Call(() -> peer.request("first")).result.get(2, TimeUnit.SECONDS));
            assertThat(peer.limiter().activeCount(), is(2));
            assertThat(peer.requests.get(), is(2));
            assertThat(peer.maximumActive.get(), is(2));
            peer.release.countDown();
            OutboundSecurityResponse original = first.result.get(5, TimeUnit.SECONDS);
            assertThat(original.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(second.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(follower.result.get(5, TimeUnit.SECONDS).requestHeaders(), is(original.requestHeaders()));
            assertThat(peer.request("third").status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(peer.requests.get(), is(3));
            assertThat(peer.limiter().activeCount(), is(0));
            assertThat(peer.limiter().queuedCount(), is(0));
        }
    }

    @TestFactory
    Stream<DynamicTest> interruptedSameKeyAndDistinctKeyWaitersReleaseTheSharedQueueSlot() {
        return Stream.of("first", "second").map(scope -> dynamicTest(scope, () -> {
            try (Peer peer = new Peer(1, "PT30S")) {
                Call leader = new Call(() -> peer.request("first"));
                assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                Call cancelled = new Call(() -> peer.request(scope));
                peer.awaitQueued(1);
                assertFailed(new Call(() -> peer.request("overflow")).result.get(2, TimeUnit.SECONDS));
                cancelled.thread.interrupt();
                assertFailed(cancelled.result.get(2, TimeUnit.SECONDS));
                assertThat(cancelled.interrupted.get(), is(true));
                assertThat(peer.limiter().queuedCount(), is(0));
                assertThat(peer.limiter().activeCount(), is(1));
                assertThat(peer.requests.get(), is(1));
                assertThat(leader.result.isDone(), is(false));
                Call replacement = new Call(() -> peer.request(scope));
                peer.awaitQueued(1);
                // Leaders awaiting capacity and same-key followers compete for the same bounded queue.
                assertFailed(new Call(() -> peer.request("first")).result.get(2, TimeUnit.SECONDS));
                peer.release.countDown();
                assertThat(leader.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                assertThat(replacement.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                assertThat(peer.requests.get(), is("first".equals(scope) ? 1 : 2));
                assertThat(peer.limiter().queuedCount(), is(0));
                assertThat(peer.limiter().activeCount(), is(0));
            }
        }));
    }

    @Test
    void timedOutNewOperationDoesNotPoisonItsKeyAndReleasesCapacity() throws Exception {
        try (Peer peer = new Peer(1, "PT0.05S")) {
            Call leader = new Call(() -> peer.request("first"));
            assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
            assertFailed(new Call(() -> peer.request("second")).result.get(2, TimeUnit.SECONDS));
            assertThat(peer.limiter().queuedCount(), is(0));
            assertThat(peer.requests.get(), is(1));
            Call follower = new Call(() -> peer.request("first"));
            peer.awaitQueued(1);
            peer.release.countDown();
            assertThat(leader.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(follower.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(peer.request("second").status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(peer.requests.get(), is(2));
        }
    }

    @Test
    void cacheHitsBypassExhaustedCapacityButExpiredTokensAreNeverForwarded() throws Exception {
        try (Peer peer = new Peer(0, "PT30S")) {
            peer.release.countDown();
            OutboundSecurityResponse cached = peer.request("cached");
            assertThat(cached.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            peer.release = new CountDownLatch(1);
            Call busy = new Call(() -> peer.request("busy"));
            peer.awaitRequests(2);
            OutboundSecurityResponse warm = new Call(() -> peer.request("cached")).result.get(2, TimeUnit.SECONDS);
            assertThat(warm.requestHeaders(), is(cached.requestHeaders()));
            assertFailed(new Call(() -> peer.request("cached", "default", 1000)).result.get(2, TimeUnit.SECONDS));
            assertThat(peer.requests.get(), is(2));
            peer.release.countDown();
            assertThat(busy.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            OutboundSecurityResponse renewed = peer.request("cached", "default", 1000);
            assertThat(renewed.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(renewed.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                       is(List.of("Bearer service-token-3")));
            assertThat(peer.requests.get(), is(3));
        }
    }

    @Test
    void preInterruptedMissDoesNotLoadButCachedTokensRemainAvailable() throws Exception {
        try (Peer peer = new Peer(0, "PT30S")) {
            Supplier<OutboundSecurityResponse> lookup = () -> {
                Thread.currentThread().interrupt();
                return peer.request("first");
            };
            Call rejected = new Call(lookup);
            assertFailed(rejected.result.get(2, TimeUnit.SECONDS));
            assertThat(rejected.interrupted.get(), is(true));
            assertThat(peer.requests.get(), is(0));
            peer.release.countDown();
            OutboundSecurityResponse cached = peer.request("first");
            Call warm = new Call(lookup);
            assertThat(warm.result.get(2, TimeUnit.SECONDS).requestHeaders(), is(cached.requestHeaders()));
            assertThat(warm.interrupted.get(), is(true));
            assertThat(peer.requests.get(), is(1));
        }
    }

    @TestFactory
    Stream<DynamicTest> nonReusableSharedOutcomesDoNotBecomeCacheEntries() {
        return Stream.of(false, true).map(error -> dynamicTest("error=" + error, () -> {
            try (Peer peer = new Peer(1, "PT30S")) {
                peer.status = error ? 503 : 200;
                peer.expiresIn = null;
                Call leader = new Call(() -> peer.request("first"));
                assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                Call follower = new Call(() -> peer.request("first"));
                peer.awaitQueued(1);
                peer.release.countDown();
                OutboundSecurityResponse first = leader.result.get(5, TimeUnit.SECONDS);
                OutboundSecurityResponse second = follower.result.get(5, TimeUnit.SECONDS);
                assertThat(first.status(), is(error
                                                     ? SecurityResponse.SecurityStatus.FAILURE
                                                     : SecurityResponse.SecurityStatus.SUCCESS));
                assertThat(second.status(), is(first.status()));
                assertThat(second.requestHeaders(), is(first.requestHeaders()));
                assertThat(peer.requests.get(), is(1));
                peer.status = 200;
                peer.expiresIn = 600;
                assertThat(peer.request("first").status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                assertThat(peer.requests.get(), is(2));
                assertThat(peer.request("first").status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                assertThat(peer.requests.get(), is(2));
                assertThat(peer.limiter().activeCount(), is(0));
                assertThat(peer.limiter().queuedCount(), is(0));
            }
        }));
    }

    @Test
    void tenantsHaveIndependentAdmissionAndTokenCaches() throws Exception {
        try (Peer peer = new Peer(0, "PT30S")) {
            Call first = new Call(() -> peer.request("first"));
            assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
            assertFailed(new Call(() -> peer.request("second")).result.get(2, TimeUnit.SECONDS));
            Call other = new Call(() -> peer.request("first", "other", 0));
            peer.awaitRequests(2);
            assertThat(first.result.isDone(), is(false));
            peer.release.countDown();
            assertThat(first.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(other.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(peer.request("first").status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(peer.request("first", "other", 0).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(peer.requests.get(), is(2));
        }
    }

    @Test
    void highCardinalityVirtualThreadBurstIsBoundedAndRecovers() throws Exception {
        try (Peer peer = new Peer(2, 0, "PT30S")) {
            Call first = new Call(() -> peer.request("first"));
            Call second = new Call(() -> peer.request("second"));
            peer.awaitRequests(2);
            List<Call> overflow = new ArrayList<>();
            for (int i = 0; i < 128; i++) {
                String scope = "scope-" + i;
                overflow.add(new Call(() -> peer.request(scope)));
            }
            for (Call caller : overflow) {
                assertFailed(caller.result.get(5, TimeUnit.SECONDS));
            }
            assertThat(peer.requests.get(), is(2));
            assertThat(peer.maximumActive.get(), is(2));
            peer.release.countDown();
            assertThat(first.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(second.result.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(peer.request("scope-0").status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(peer.requests.get(), is(3));
        }
    }

    @TestFactory
    Stream<DynamicTest> zeroQueueRejectsSameKeyAndDistinctKeyOverflowWithoutRemoteWork() {
        return Stream.of("first", "second").map(scope -> dynamicTest(scope, () -> {
            try (Peer peer = new Peer(0, "PT30S");
                 var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                Future<OutboundSecurityResponse> leader = executor.submit(() -> peer.request("first"));
                try {
                    assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                    OutboundSecurityResponse rejected = executor.submit(() -> peer.request(scope)).get(2, TimeUnit.SECONDS);
                    assertThat(rejected.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                    assertThat(rejected.requestHeaders().containsKey(HeaderNames.AUTHORIZATION.defaultCase()), is(false));
                    assertThat(peer.requests.get(), is(1));
                    assertThat(leader.isDone(), is(false));
                    peer.release.countDown();
                    assertThat(leader.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                    assertThat(peer.request(scope).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                    assertThat(peer.requests.get(), is("first".equals(scope) ? 1 : 2));
                } finally {
                    peer.release.countDown();
                }
            }
        }));
    }

    @Test
    void admittedSameKeyFollowerWaitsForItsSharedResultBeyondAdmissionTimeout() throws Exception {
        try (Peer peer = new Peer(1, "PT0.01S");
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<OutboundSecurityResponse> leader = executor.submit(() -> peer.request("first"));
            try {
                assertThat(peer.entered.await(5, TimeUnit.SECONDS), is(true));
                Future<OutboundSecurityResponse> follower = executor.submit(() -> peer.request("first"));
                assertThrows(TimeoutException.class, () -> follower.get(1500, TimeUnit.MILLISECONDS));
                peer.release.countDown();
                OutboundSecurityResponse first = leader.get(5, TimeUnit.SECONDS);
                OutboundSecurityResponse second = follower.get(5, TimeUnit.SECONDS);
                assertThat(first.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                assertThat(second.requestHeaders(), is(first.requestHeaders()));
                assertThat(peer.requests.get(), is(1));
            } finally {
                peer.release.countDown();
            }
        }
    }

    private static void assertFailed(OutboundSecurityResponse response) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElseThrow(), is("Client Credentials Grant failed"));
        assertThat(response.requestHeaders().containsKey(HeaderNames.AUTHORIZATION.defaultCase()), is(false));
    }

    private static final class Peer implements AutoCloseable {
        private final CountDownLatch entered = new CountDownLatch(1);
        private final AtomicInteger requests = new AtomicInteger();
        private final AtomicInteger active = new AtomicInteger();
        private final AtomicInteger maximumActive = new AtomicInteger();
        private final WebServer server;
        private final OidcProvider provider;
        private volatile CountDownLatch release = new CountDownLatch(1);
        private volatile Integer expiresIn = 600;
        private volatile int status = 200;

        private Peer(int maxQueued, String admissionTimeout) {
            this(1, maxQueued, admissionTimeout);
        }

        private Peer(int maxConcurrent, int maxQueued, String admissionTimeout) {
            server = WebServer.builder().port(0).routing(routing -> routing.post("/token", (request, response) -> {
                assertThat(request.content().as(Parameters.class).first("grant_type").orElseThrow(), is("client_credentials"));
                maximumActive.accumulateAndGet(active.incrementAndGet(), Math::max);
                int number = requests.incrementAndGet();
                entered.countDown();
                try {
                    if (!release.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Test did not release the Token Endpoint");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                } finally {
                    active.decrementAndGet();
                }
                JsonObject.Builder body = JsonObject.builder();
                if (status == 200) {
                    body.set("access_token", "service-token-" + number).set("token_type", "Bearer");
                    if (expiresIn != null) {
                        body.set("expires_in", expiresIn);
                    }
                } else {
                    body.set("error", "temporarily_unavailable");
                }
                response.status(status).header(HeaderValues.CONTENT_TYPE_JSON)
                        .header(HeaderNames.CACHE_CONTROL, "no-store").header(HeaderNames.PRAGMA, "no-cache")
                        .send(body.build().toString());
            })).build().start();
            String issuer = "http://localhost:" + server.port();
            Config config = Config.builder().disableEnvironmentVariablesSource().disableSystemPropertiesSource()
                    .sources(ConfigSources.create(Map.of("issuer", issuer,
                                                          "client-id", "service-client",
                                                          "client-secret", "service-secret",
                                                          "endpoints.tls-required", "false",
                                                          "endpoints.token-endpoint-uri", issuer + "/token",
                                                          "client-credentials-remote-work.max-concurrent",
                                                          Integer.toString(maxConcurrent),
                                                          "client-credentials-remote-work.max-queued",
                                                          Integer.toString(maxQueued),
                                                          "client-credentials-remote-work.admission-timeout", admissionTimeout)))
                    .build();
            OidcTenantConfig tenant = OidcTenantConfig.create(config);
            provider = OidcProvider.create(OidcProviderConfig.builder().putTenant("default", tenant).putTenant("other", tenant)
                                                  .defaultTenant("default")
                                                  .tenantResolution(resolution -> resolution.headerName("X-Test-Tenant"))
                                                  .buildPrototype());
            for (String id : List.of("default", "other")) {
                assertThat(provider.tenantRuntimeRegistry().tenantContext(id).orElseThrow().ready(), is(true));
            }
        }

        @Override
        public void close() {
            release.countDown();
            try {
                provider.close();
            } finally {
                server.stop();
            }
        }

        private OutboundSecurityResponse request(String scope) {
            return request(scope, "default", 0);
        }

        private OutboundSecurityResponse request(String scope, String tenant, long timeShiftSeconds) {
            EndpointConfig endpoint = EndpointConfig.builder().customObject(OidcOutboundPolicyConfig.class,
                    OidcOutboundPolicyConfig.builder().strategy(OidcOutboundStrategy.CLIENT_CREDENTIALS)
                            .addClientCredentialsScope(scope).buildPrototype()).build();
            return provider.outboundSecurity(OidcProviderTest.request(null, SecurityEnvironment.builder()
                                                     .header("X-Test-Tenant", tenant).build()),
                                             SecurityEnvironment.builder().targetUri(URI.create("https://downstream.example/api"))
                                                     .time(SecurityTime.builder().shiftBySeconds(timeShiftSeconds).build())
                                                     .build(), endpoint);
        }

        private OidcRemoteWorkLimiter limiter() {
            return provider.tenantRuntimeRegistry().tenantContext("default").orElseThrow().clientCredentialsRemoteWorkLimiter();
        }

        private void awaitRequests(int expected) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (requests.get() < expected && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            assertThat(requests.get(), is(expected));
        }

        private void awaitQueued(int expected) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (limiter().queuedCount() != expected && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            assertThat(limiter().queuedCount(), is(expected));
        }
    }

    private static final class Call {
        private final CompletableFuture<OutboundSecurityResponse> result = new CompletableFuture<>();
        private final AtomicBoolean interrupted = new AtomicBoolean();
        private final Thread thread;

        private Call(Supplier<OutboundSecurityResponse> request) {
            thread = Thread.ofVirtual().start(() -> {
                try {
                    OutboundSecurityResponse response = request.get();
                    interrupted.set(Thread.currentThread().isInterrupted());
                    result.complete(response);
                } catch (Throwable e) {
                    interrupted.set(Thread.currentThread().isInterrupted());
                    result.completeExceptionally(e);
                }
            });
        }
    }
}
