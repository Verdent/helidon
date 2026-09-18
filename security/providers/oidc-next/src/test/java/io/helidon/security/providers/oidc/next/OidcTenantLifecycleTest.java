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

import java.lang.reflect.Proxy;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import io.helidon.security.AuthenticationResponse;
import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.webclient.api.WebClient;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcTenantLifecycleTest {
    @Test
    void closeDoesNotInitializeUnusedTenantsAndRejectsLaterAccess() {
        AtomicInteger attempts = new AtomicInteger();
        OidcTenantRuntimeRegistry registry = registryWithInitializer((tenantId, config) -> {
            attempts.incrementAndGet();
            return OidcTenantContext.ready(tenantId, config);
        });

        registry.close();
        registry.close();

        assertThat(attempts.get(), is(0));
        assertThat(registry.cachedTenantCount(), is(0));
        assertThrows(IllegalStateException.class, () -> registry.tenantContext("tenant"));
        assertThrows(IllegalStateException.class, () -> registry.cookieStateHandler("tenant"));
        assertThrows(IllegalStateException.class,
                     () -> registry.tenantConfig(OidcProviderTest.request(null, SecurityEnvironment.create())));
    }

    @Test
    void closeReleasesEveryReadyClientOnceAndClearsContexts() {
        AtomicInteger closes = new AtomicInteger();
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("first", OidcTenantConfig.create())
                .putTenant("second", OidcTenantConfig.create())
                .putTenant("disabled", OidcTenantConfig.builder().enabled(false).buildPrototype())
                .buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(config,
                OidcTenantContextFactory.create((tenantId, tenant) -> OidcTenantContext.ready(tenantId, tenant,
                        OidcProviderMetadata.fromStaticConfig(tenant), trackingClient(closes::incrementAndGet))));
        config.tenants().keySet().forEach(registry::tenantContext);

        registry.close();
        registry.close();

        assertThat(closes.get(), is(2));
        assertThat(registry.cachedTenantCount(), is(0));
    }

    @Test
    void closeAttemptsAllClientsEvenWhenCleanupFails() {
        AtomicInteger closes = new AtomicInteger();
        IllegalStateException first = new IllegalStateException("first close failure");
        IllegalArgumentException second = new IllegalArgumentException("second close failure");
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("first", OidcTenantConfig.create())
                .putTenant("second", OidcTenantConfig.create())
                .putTenant("third", OidcTenantConfig.create())
                .buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(config,
                OidcTenantContextFactory.create((tenantId, tenant) -> OidcTenantContext.ready(tenantId, tenant,
                        OidcProviderMetadata.fromStaticConfig(tenant), trackingClient(() -> {
                            closes.incrementAndGet();
                            if ("first".equals(tenantId)) {
                                throw first;
                            }
                            if ("second".equals(tenantId)) {
                                throw second;
                            }
                        }))));
        config.tenants().keySet().forEach(registry::tenantContext);

        RuntimeException thrown = assertThrows(RuntimeException.class, registry::close);

        assertThat(closes.get(), is(3));
        assertThat(thrown.getSuppressed().length, is(1));
        assertThat(Set.of(thrown, thrown.getSuppressed()[0]), is(Set.of(first, second)));
        registry.close();
        assertThat(closes.get(), is(3));
    }

    @Test
    void closeDoesNotRepeatFailedInitializationCleanup() {
        AtomicInteger closes = new AtomicInteger();
        OidcTenantRuntimeRegistry registry = registryWithInitializer((tenantId, config) -> {
            WebClient client = trackingClient(closes::incrementAndGet);
            // Failed initialization owns cleanup before returning a context without runtime resources.
            client.closeResource();
            return OidcTenantContext.failed(tenantId, config, new IllegalArgumentException("invalid metadata"));
        });
        assertThat(registry.tenantContext("tenant").orElseThrow().state(), is(OidcTenantState.FAILED));
        assertThat(closes.get(), is(1));

        registry.close();
        registry.close();

        assertThat(closes.get(), is(1));
    }

    @Test
    void closeDoesNotWaitForInitializationAndReleasesItsLateClient() throws Exception {
        AtomicInteger closes = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        OidcTenantRuntimeRegistry registry = registryWithInitializer((tenantId, config) -> {
            OidcTenantContext ready = OidcTenantContext.ready(tenantId, config,
                    OidcProviderMetadata.fromStaticConfig(config), trackingClient(closes::incrementAndGet));
            entered.countDown();
            await(finish);
            return ready;
        });
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<?> initialized = executor.submit(() -> registry.tenantContext("tenant"));
            try {
                assertThat(entered.await(5, TimeUnit.SECONDS), is(true));
                executor.submit(registry::close).get(2, TimeUnit.SECONDS);
                assertThat(closes.get(), is(0));
                assertThrows(IllegalStateException.class, () -> registry.tenantContext("tenant"));
                finish.countDown();
                ExecutionException failure = assertThrows(ExecutionException.class,
                                                          () -> initialized.get(5, TimeUnit.SECONDS));
                assertThat(failure.getCause(), instanceOf(IllegalStateException.class));
                assertThat(closes.get(), is(1));
                registry.close();
                assertThat(closes.get(), is(1));
            } finally {
                finish.countDown();
            }
        }
    }

    @Test
    void publicationAndConcurrentCloseNeverLoseOrDoubleCloseAClient() throws Exception {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int iteration = 0; iteration < 64; iteration++) {
                AtomicInteger created = new AtomicInteger();
                AtomicInteger closed = new AtomicInteger();
                CountDownLatch start = new CountDownLatch(1);
                OidcTenantRuntimeRegistry registry = registryWithInitializer((tenantId, config) -> {
                    created.incrementAndGet();
                    return OidcTenantContext.ready(tenantId, config,
                            OidcProviderMetadata.fromStaticConfig(config), trackingClient(closed::incrementAndGet));
                });
                Future<?> initializer = executor.submit(() -> {
                    await(start);
                    try {
                        registry.tenantContext("tenant");
                    } catch (IllegalStateException e) {
                        assertThat(e.getMessage(), is("OIDC tenant runtime is closed"));
                    }
                });
                Future<?> firstClose = executor.submit(() -> {
                    await(start);
                    registry.close();
                });
                Future<?> secondClose = executor.submit(() -> {
                    await(start);
                    registry.close();
                });
                start.countDown();
                initializer.get(5, TimeUnit.SECONDS);
                firstClose.get(5, TimeUnit.SECONDS);
                secondClose.get(5, TimeUnit.SECONDS);
                assertThat(closed.get(), is(created.get()));
                assertThat(registry.cachedTenantCount(), is(0));
            }
        }
    }

    @Test
    void providerCloseIsTerminalAndIdempotent() {
        OidcProvider provider = OidcProvider.create();
        ProviderRequest request = OidcProviderTest.request(null, SecurityEnvironment.create());

        provider.close();
        provider.close();

        assertThrows(IllegalStateException.class, () -> provider.authenticate(request));
        assertThrows(IllegalStateException.class,
                     () -> provider.isOutboundSupported(request, outboundEnvironment(), EndpointConfig.create()));
        assertThrows(IllegalStateException.class,
                     () -> provider.outboundSecurity(request, outboundEnvironment(), EndpointConfig.create()));
        assertThrows(IllegalStateException.class, () -> OidcFeature.create(provider));
    }

    @Test
    void disabledTenantReturnsDisabledContextAndFailsPredictably() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .enabled(false)
                .protectedResource(OidcProtectedResourceConfig.create())
                .buildPrototype();
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("tenant", tenant)
                .buildPrototype();
        OidcProvider provider = OidcProvider.create(config);
        ProviderRequest request = OidcProviderTest.request(OidcEndpointPolicy.protectedResource(),
                                                           SecurityEnvironment.create());
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.clientCredentialsGrant())
                .build();
        SecurityEnvironment outboundEnv = outboundEnvironment();

        AuthenticationResponse authenticationResponse = provider.authenticate(request);
        OutboundSecurityResponse outboundResponse = provider.outboundSecurity(request,
                                                                              outboundEnv,
                                                                              outboundConfig);

        assertThat(OidcTenantRuntimeRegistry.create(config).tenantContext("tenant").orElseThrow().state(),
                   is(OidcTenantState.DISABLED));
        assertThat(authenticationResponse.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(authenticationResponse.statusCode().orElse(-1), is(503));
        assertThat(authenticationResponse.description().orElse(""), is("OIDC tenant is unavailable"));
        assertThat(provider.isOutboundSupported(request, outboundEnv, outboundConfig), is(true));
        assertThat(outboundResponse.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(outboundResponse.description().orElse(""), is("OIDC tenant is unavailable"));
    }

    @Test
    void failedTenantContextIsCached() {
        AtomicInteger attempts = new AtomicInteger();
        RuntimeException failureCause = new IllegalStateException("tenant failed");
        OidcTenantRuntimeRegistry registry = registryWithInitializer((tenantId, tenantConfig) -> {
            attempts.incrementAndGet();
            return OidcTenantContext.failed(tenantId, tenantConfig, failureCause);
        });

        OidcTenantContext first = registry.tenantContext("tenant").orElseThrow();
        OidcTenantContext second = registry.tenantContext("tenant").orElseThrow();

        assertThat(first.state(), is(OidcTenantState.FAILED));
        assertThat(first.failureCause().orElseThrow(), sameInstance(failureCause));
        assertThat(second, sameInstance(first));
        assertThat(attempts.get(), is(1));
        assertThat(registry.cachedTenantCount(), is(1));
    }

    @Test
    void thrownInitializationFailureDoesNotPoisonRegistry() {
        AtomicInteger attempts = new AtomicInteger();
        RuntimeException failure = new IllegalStateException("initializer contract violation");
        OidcTenantRuntimeRegistry registry = registryWithInitializer((tenantId, tenantConfig) -> {
            if (attempts.incrementAndGet() == 1) {
                throw failure;
            }
            return OidcTenantContext.ready(tenantId, tenantConfig);
        });

        RuntimeException thrown = assertThrows(RuntimeException.class, () -> registry.tenantContext("tenant"));
        OidcTenantContext context = registry.tenantContext("tenant").orElseThrow();

        assertThat(thrown, sameInstance(failure));
        assertThat(context.state(), is(OidcTenantState.READY));
        assertThat(attempts.get(), is(2));
        assertThat(registry.cachedTenantCount(), is(1));
    }

    @Test
    void rootConfiguredRetryIntervalControlsRuntimeReinitialization() {
        MutableClock clock = MutableClock.create(Instant.parse("2026-09-17T00:00:00Z"));
        AtomicInteger attempts = new AtomicInteger();
        OidcProviderConfig config = OidcProviderConfig.builder()
                .initializationRetryInterval(Duration.ofSeconds(2)).buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(config,
                OidcTenantContextFactory.create((tenantId, tenant) -> attempts.incrementAndGet() == 1
                        ? OidcTenantContext.retryableFailure(tenantId, tenant, new IllegalStateException("discovery failed"))
                        : OidcTenantContext.ready(tenantId, tenant)),
                clock);

        OidcTenantContext failed = registry.tenantContext("default").orElseThrow();
        assertThat(failed.state(), is(OidcTenantState.FAILED));
        clock.advance(Duration.ofMillis(1_999));
        assertThat(registry.tenantContext("default").orElseThrow(), sameInstance(failed));
        assertThat(attempts.get(), is(1));
        clock.advance(Duration.ofMillis(1));
        OidcTenantContext ready = registry.tenantContext("default").orElseThrow();
        try {
            assertThat(ready.state(), is(OidcTenantState.READY));
            assertThat(attempts.get(), is(2));
        } finally {
            if (ready.ready()) {
                ready.webClient().closeResource();
            }
        }
    }

    @Test
    void retryableTenantFailureIsCachedThenRetriedAsOneCohort() throws Exception {
        int taskCount = 8;
        MutableClock clock = MutableClock.create(Instant.parse("2026-09-15T00:00:00Z"));
        AtomicInteger attempts = new AtomicInteger();
        CountDownLatch retryStarted = new CountDownLatch(1);
        CountDownLatch finishRetry = new CountDownLatch(1);
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .initializationRetryInterval(Duration.ofSeconds(10))
                .buildPrototype();
        OidcProviderConfig config = providerConfig(tenantConfig);
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                config,
                OidcTenantContextFactory.create((tenantId, resolvedConfig) -> {
                    if (attempts.incrementAndGet() == 1) {
                        return OidcTenantContext.retryableFailure(tenantId,
                                                                 resolvedConfig,
                                                                 new IllegalStateException("discovery failed"));
                    }
                    retryStarted.countDown();
                    await(finishRetry);
                    return OidcTenantContext.ready(tenantId, resolvedConfig);
                }),
                clock);

        OidcTenantContext failed = registry.tenantContext("tenant").orElseThrow();
        assertThat(registry.tenantContext("tenant").orElseThrow(), sameInstance(failed));
        assertThat(attempts.get(), is(1));
        clock.advance(Duration.ofSeconds(9));
        assertThat(registry.tenantContext("tenant").orElseThrow(), sameInstance(failed));
        assertThat(attempts.get(), is(1));
        clock.advance(Duration.ofSeconds(1));

        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        try {
            List<Future<OidcTenantContext>> futures = new ArrayList<>();
            for (int i = 0; i < taskCount; i++) {
                futures.add(executor.submit(() -> registry.tenantContext("tenant").orElseThrow()));
            }
            assertThat(retryStarted.await(5, TimeUnit.SECONDS), is(true));
            finishRetry.countDown();
            OidcTenantContext ready = futures.getFirst().get(5, TimeUnit.SECONDS);
            for (Future<OidcTenantContext> future : futures) {
                assertThat(future.get(5, TimeUnit.SECONDS), sameInstance(ready));
            }
            assertThat(ready.state(), is(OidcTenantState.READY));
            assertThat(attempts.get(), is(2));
        } finally {
            finishRetry.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void tenantInitializationIsSingleFlight() throws Exception {
        int taskCount = 8;
        AtomicInteger attempts = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch enteredInitializer = new CountDownLatch(1);
        CountDownLatch finishInitializer = new CountDownLatch(1);
        OidcTenantRuntimeRegistry registry = registryWithInitializer((tenantId, tenantConfig) -> {
            attempts.incrementAndGet();
            enteredInitializer.countDown();
            await(finishInitializer);
            return OidcTenantContext.ready(tenantId, tenantConfig);
        });
        List<Future<OidcTenantContext>> futures = new ArrayList<>();
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

        try {
            for (int i = 0; i < taskCount; i++) {
                futures.add(executor.submit(() -> {
                    await(start);
                    return registry.tenantContext("tenant").orElseThrow();
                }));
            }

            start.countDown();
            assertThat(enteredInitializer.await(5, TimeUnit.SECONDS), is(true));
            finishInitializer.countDown();
            OidcTenantContext first = futures.getFirst().get(5, TimeUnit.SECONDS);
            for (Future<OidcTenantContext> future : futures) {
                assertThat(future.get(5, TimeUnit.SECONDS), sameInstance(first));
            }

            assertThat(attempts.get(), is(1));
            assertThat(registry.cachedTenantCount(), is(1));
        } finally {
            finishInitializer.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void collidingTenantIdsInitializeIndependently() throws Exception {
        String firstTenantId = "Aa";
        String secondTenantId = "BB";
        assertThat(firstTenantId.hashCode(), is(secondTenantId.hashCode()));

        CountDownLatch enteredFirstInitializer = new CountDownLatch(1);
        CountDownLatch finishFirstInitializer = new CountDownLatch(1);
        CountDownLatch enteredSecondInitializer = new CountDownLatch(1);
        OidcTenantConfig tenantConfig = OidcTenantConfig.create();
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant(firstTenantId, tenantConfig)
                .putTenant(secondTenantId, tenantConfig)
                .buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                config,
                OidcTenantContextFactory.create((tenantId, resolvedConfig) -> {
                    if (firstTenantId.equals(tenantId)) {
                        enteredFirstInitializer.countDown();
                        await(finishFirstInitializer);
                    } else {
                        enteredSecondInitializer.countDown();
                    }
                    return OidcTenantContext.ready(tenantId, resolvedConfig);
                }));
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

        try {
            Future<OidcTenantContext> first = executor.submit(
                    () -> registry.tenantContext(firstTenantId).orElseThrow());
            assertThat(enteredFirstInitializer.await(5, TimeUnit.SECONDS), is(true));

            Future<OidcTenantContext> second = executor.submit(
                    () -> registry.tenantContext(secondTenantId).orElseThrow());
            assertThat(enteredSecondInitializer.await(5, TimeUnit.SECONDS), is(true));

            finishFirstInitializer.countDown();
            assertThat(first.get(5, TimeUnit.SECONDS).tenantId(), is(firstTenantId));
            assertThat(second.get(5, TimeUnit.SECONDS).tenantId(), is(secondTenantId));
            assertThat(registry.cachedTenantCount(), is(2));
        } finally {
            finishFirstInitializer.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void tenantInitializationIsLazyByDefault() {
        AtomicInteger attempts = new AtomicInteger();
        OidcTenantRuntimeRegistry registry = registryWithInitializer((tenantId, tenantConfig) -> {
            attempts.incrementAndGet();
            return OidcTenantContext.ready(tenantId, tenantConfig);
        });

        assertThat(attempts.get(), is(0));

        registry.tenantContext("tenant").orElseThrow();

        assertThat(attempts.get(), is(1));
    }

    @Test
    void outboundSupportCheckDoesNotInitializeTenant() {
        AtomicInteger attempts = new AtomicInteger();
        OidcProviderConfig config = providerConfig(OidcTenantConfig.builder()
                                                   .clientId("client-id")
                                                   .clientSecret("client-secret")
                                                   .buildPrototype());
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                config,
                OidcTenantContextFactory.create((tenantId, tenantConfig) -> {
                    attempts.incrementAndGet();
                    return OidcTenantContext.failed(tenantId, tenantConfig);
                }));
        OidcOutboundOrchestrator outbound = new OidcOutboundOrchestrator(config, registry);
        ProviderRequest request = OidcProviderTest.request(null, SecurityEnvironment.create());
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.clientCredentialsGrant())
                .build();
        SecurityEnvironment outboundEnv = outboundEnvironment();

        boolean supported = outbound.isSupported(request, outboundEnv, outboundConfig);

        assertThat(supported, is(true));
        assertThat(attempts.get(), is(0));

        OutboundSecurityResponse response = outbound.secure(request, outboundEnv, outboundConfig);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), is("OIDC tenant is unavailable"));
        assertThat(attempts.get(), is(1));
    }

    @Test
    void failedTenantFailsPredictably() {
        RuntimeException failureCause = new IllegalStateException("tenant failed");
        OidcProviderConfig config = providerConfig(OidcTenantConfig.create());
        OidcTenantContextFactory.TenantInitializer initializer = (tenantId, tenantConfig) ->
                OidcTenantContext.failed(tenantId, tenantConfig, failureCause);
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                config,
                OidcTenantContextFactory.create(initializer));
        OidcAuthenticationOrchestrator authentication = OidcAuthenticationOrchestrator.create(config, registry);
        OidcOutboundOrchestrator outbound = new OidcOutboundOrchestrator(config, registry);
        ProviderRequest request = OidcProviderTest.request(OidcEndpointPolicy.protectedResource(),
                                                           SecurityEnvironment.create());
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.clientCredentialsGrant())
                .build();
        SecurityEnvironment outboundEnv = outboundEnvironment();

        AuthenticationResponse authenticationResponse = authentication.authenticate(request);
        OutboundSecurityResponse outboundResponse = outbound.secure(request,
                                                                    outboundEnv,
                                                                    outboundConfig);

        assertThat(authenticationResponse.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(authenticationResponse.statusCode().orElse(-1), is(503));
        assertThat(authenticationResponse.description().orElse(""), is("OIDC tenant is unavailable"));
        assertThat(authenticationResponse.throwable().isEmpty(), is(true));
        assertThat(outbound.isSupported(request, outboundEnv, outboundConfig), is(true));
        assertThat(outboundResponse.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(outboundResponse.description().orElse(""), is("OIDC tenant is unavailable"));
        assertThat(outboundResponse.throwable().isEmpty(), is(true));
    }

    @Test
    void runtimeResourcesAreAvailableOnlyForReadyTenant() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.create();
        OidcTenantContext ready = OidcTenantContext.ready("tenant", tenantConfig);
        OidcTenantContext disabled = OidcTenantContext.disabled("tenant", tenantConfig);
        OidcTenantContext failed = OidcTenantContext.failed("tenant", tenantConfig);

        ready.metadata();
        ready.endpointClient();
        ready.jwkSetManager();
        ready.tokenValidation();
        ready.cookieStateHandler();

        assertThrows(IllegalStateException.class, disabled::endpointClient);
        assertThrows(IllegalStateException.class, failed::jwkSetManager);
        assertThrows(IllegalStateException.class, disabled::tokenValidation);
        assertThrows(IllegalStateException.class, failed::cookieStateHandler);
        assertThat(failed.failureCause().isEmpty(), is(true));
    }

    private static OidcTenantRuntimeRegistry registryWithInitializer(
            OidcTenantContextFactory.TenantInitializer initializer) {
        return OidcTenantRuntimeRegistry.create(providerConfig(OidcTenantConfig.create()),
                                                OidcTenantContextFactory.create(initializer));
    }

    private static WebClient trackingClient(Runnable onClose) {
        // Test double of the public WebClient interface; no private implementation state is accessed.
        return (WebClient) Proxy.newProxyInstance(WebClient.class.getClassLoader(), new Class<?>[] {WebClient.class},
                (_, method, _) -> {
                    if ("closeResource".equals(method.getName())) {
                        onClose.run();
                        return null;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static OidcProviderConfig providerConfig(OidcTenantConfig tenantConfig) {
        return OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .buildPrototype();
    }

    private static SecurityEnvironment outboundEnvironment() {
        return SecurityEnvironment.builder()
                .targetUri(URI.create("https://api.example.com/resource"))
                .transport("https")
                .path("/resource")
                .method("GET")
                .build();
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static final class MutableClock extends Clock {
        private volatile Instant instant;
        private final ZoneId zone;

        private MutableClock(Instant instant, ZoneId zone) {
            this.instant = instant;
            this.zone = zone;
        }

        private static MutableClock create(Instant instant) {
            return new MutableClock(instant, ZoneId.of("UTC"));
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant, zone);
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
