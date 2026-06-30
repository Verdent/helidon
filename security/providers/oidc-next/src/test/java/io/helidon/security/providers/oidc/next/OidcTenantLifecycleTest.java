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
import java.util.concurrent.CountDownLatch;
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

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcTenantLifecycleTest {
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
}
