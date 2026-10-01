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

import java.math.BigDecimal;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.parameters.Parameters;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.Principal;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityContext;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ServerTest
@Execution(ExecutionMode.SAME_THREAD)
class OidcTokenExchangeGrantTest {
    private static final String CLIENT_ID = "client/id";
    private static final String CLIENT_SECRET = "client+secret=value";
    private static final String SUBJECT_TOKEN = "incoming-access-token";
    private static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String EXISTING_HEADER_NAME = "X-Existing";
    private static final String EXISTING_HEADER_VALUE = "existing-value";

    private static final AtomicInteger METADATA_REQUEST_COUNT = new AtomicInteger();
    private static final AtomicInteger REQUEST_COUNT = new AtomicInteger();
    private static final AtomicInteger ACTIVE_REQUESTS = new AtomicInteger();
    private static final AtomicInteger MAX_ACTIVE_REQUESTS = new AtomicInteger();
    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();
    private static volatile CountDownLatch tokenRequestStarted;
    private static volatile CountDownLatch releaseTokenResponse;
    private static volatile CountDownLatch metadataRequestStarted;
    private static volatile CountDownLatch releaseMetadataResponse;

    private static volatile int metadataResponseStatus;
    private static volatile int responseStatus;
    private static volatile String responseBody;
    private static volatile String providerMetadata;
    private static volatile boolean dynamicTokenResponse;
    private static volatile Integer dynamicExpiresIn;

    private URI issuer;
    private URI tokenEndpointUri;

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.get("/.well-known/openid-configuration", (_, response) -> {
            METADATA_REQUEST_COUNT.incrementAndGet();
            CountDownLatch started = metadataRequestStarted;
            if (started != null) {
                started.countDown();
            }
            CountDownLatch release = releaseMetadataResponse;
            if (release != null) {
                await(release);
            }
            response.status(metadataResponseStatus).header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(providerMetadata);
        });
        routing.post("/token", OidcTokenExchangeGrantTest::handleTokenEndpoint);
    }

    @BeforeEach
    void setUp(URI serverUri) {
        issuer = URI.create(serverUri.toString().substring(0, serverUri.toString().length() - 1));
        tokenEndpointUri = serverUri.resolve("token");
        responseStatus = 200;
        metadataResponseStatus = 200;
        responseBody = tokenExchangeResponse("exchanged-access-token", 600).toString();
        providerMetadata = JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .setStrings("grant_types_supported", List.of(TOKEN_EXCHANGE_GRANT))
                .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                .build()
                .toString();
        dynamicTokenResponse = false;
        dynamicExpiresIn = 600;
        METADATA_REQUEST_COUNT.set(0);
        REQUEST_COUNT.set(0);
        ACTIVE_REQUESTS.set(0);
        MAX_ACTIVE_REQUESTS.set(0);
        RECORDED_REQUEST.set(null);
        tokenRequestStarted = null;
        releaseTokenResponse = null;
        metadataRequestStarted = null;
        releaseMetadataResponse = null;
    }

    @Test
    void grantAdmissionBoundsMixedDeferredDiscoveryAndInterruptionDoesNotCancelItsLoader() throws Exception {
        for (boolean metadataFails : List.of(false, true)) {
            METADATA_REQUEST_COUNT.set(0);
            REQUEST_COUNT.set(0);
            metadataRequestStarted = new CountDownLatch(1);
            releaseMetadataResponse = new CountDownLatch(1);
            metadataResponseStatus = metadataFails ? 503 : 200;
            providerMetadata = JsonObject.builder().set("issuer", issuer.toString())
                    .set("token_endpoint", tokenEndpointUri.toString())
                    .setStrings("grant_types_supported", List.of("client_credentials", TOKEN_EXCHANGE_GRANT))
                    .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                    .build().toString();
            OidcRemoteWorkConfig limits = OidcRemoteWorkConfig.builder().maxConcurrent(2).maxQueued(0).buildPrototype();
            OidcTenantConfig tenant = OidcTenantConfig.builder(confidentialTenantFromWellKnown())
                    .clientCredentialsRemoteWork(limits).tokenExchangeRemoteWork(limits).buildPrototype();
            try (OidcProvider provider = endpointPolicyProvider(tenant);
                 ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                try {
                    OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("default").orElseThrow();
                    assertThat(context.ready(), is(true));
                    assertThat(METADATA_REQUEST_COUNT.get(), is(0));
                    OidcRemoteWorkLimiter cc = context.clientCredentialsRemoteWorkLimiter();
                    OidcRemoteWorkLimiter exchange = context.tokenExchangeRemoteWorkLimiter();
                    EndpointConfig first = clientCredentialsEndpointConfig("first");
                    EndpointConfig second = clientCredentialsEndpointConfig("second");
                    Future<OutboundSecurityResponse> loader = executor.submit(() -> provider.outboundSecurity(
                            providerRequest(), outboundEnvironment(), first));
                    assertThat(metadataRequestStarted.await(5, TimeUnit.SECONDS), is(true));
                    AtomicReference<Thread> cancelledThread = new AtomicReference<>();
                    AtomicBoolean interrupted = new AtomicBoolean();
                    Future<OutboundSecurityResponse> cancelled = executor.submit(() -> {
                        cancelledThread.set(Thread.currentThread());
                        OutboundSecurityResponse result = provider.outboundSecurity(providerRequest(), outboundEnvironment(),
                                                                                    second);
                        interrupted.set(Thread.currentThread().isInterrupted());
                        return result;
                    });
                    Future<OutboundSecurityResponse> exchangeOne = executor.submit(() -> provider.outboundSecurity(
                            providerRequest("subject-one"), outboundEnvironment(), tokenExchangeEndpointConfig()));
                    Future<OutboundSecurityResponse> exchangeTwo = executor.submit(() -> provider.outboundSecurity(
                            providerRequest("subject-two"), outboundEnvironment(), tokenExchangeEndpointConfig()));
                    awaitActive(cc, 2);
                    awaitActive(exchange, 2);
                    OutboundSecurityResponse ccOverflow = executor.submit(() -> provider.outboundSecurity(providerRequest(),
                            outboundEnvironment(), clientCredentialsEndpointConfig("overflow"))).get(2, TimeUnit.SECONDS);
                    OutboundSecurityResponse exchangeOverflow = executor.submit(() -> provider.outboundSecurity(
                            providerRequest("subject-overflow"), outboundEnvironment(), tokenExchangeEndpointConfig()))
                            .get(2, TimeUnit.SECONDS);
                    assertThat(ccOverflow.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                    assertThat(exchangeOverflow.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                    assertThat(ccOverflow.requestHeaders().containsKey(HeaderNames.AUTHORIZATION.defaultCase()), is(false));
                    assertThat(exchangeOverflow.requestHeaders().containsKey(HeaderNames.AUTHORIZATION.defaultCase()), is(false));
                    assertThat(METADATA_REQUEST_COUNT.get(), is(1));
                    assertThat(REQUEST_COUNT.get(), is(0));

                    cancelledThread.get().interrupt();
                    assertThat(cancelled.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.FAILURE));
                    assertThat(interrupted.get(), is(true));
                    assertThat(cc.activeCount(), is(1));
                    assertThat(loader.isDone(), is(false));
                    Future<OutboundSecurityResponse> replacement = executor.submit(() -> provider.outboundSecurity(
                            providerRequest(), outboundEnvironment(), second));
                    awaitActive(cc, 2);
                    assertThat(exchange.activeCount(), is(2));
                    assertThat(METADATA_REQUEST_COUNT.get(), is(1));
                    releaseMetadataResponse.countDown();
                    for (Future<OutboundSecurityResponse> result : List.of(loader, replacement, exchangeOne, exchangeTwo)) {
                        OutboundSecurityResponse response = result.get(5, TimeUnit.SECONDS);
                        assertThat(response.status(), is(metadataFails
                                                                 ? SecurityResponse.SecurityStatus.FAILURE
                                                                 : SecurityResponse.SecurityStatus.SUCCESS));
                        if (metadataFails) {
                            assertThat(response.requestHeaders().containsKey(HeaderNames.AUTHORIZATION.defaultCase()), is(false));
                        }
                    }
                    assertThat(cc.activeCount(), is(0));
                    assertThat(exchange.activeCount(), is(0));
                    assertThat(cc.queuedCount(), is(0));
                    assertThat(exchange.queuedCount(), is(0));
                    OutboundSecurityResponse repeated = provider.outboundSecurity(providerRequest(), outboundEnvironment(),
                                                                                  first);
                    assertThat(repeated.status(), is(metadataFails
                                                             ? SecurityResponse.SecurityStatus.FAILURE
                                                             : SecurityResponse.SecurityStatus.SUCCESS));
                    assertThat(METADATA_REQUEST_COUNT.get(), is(1));
                    assertThat(REQUEST_COUNT.get(), is(metadataFails ? 0 : 4));
                    assertThat(context.ready(), is(true));
                } finally {
                    releaseMetadataResponse.countDown();
                }
            }
        }
    }

    @Test
    void tokenExchangeObtainsTokenAndUsesClientSecretBasic() {
        OidcProvider provider = provider(confidentialTenant(), tokenExchangeTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(SUBJECT_TOKEN), outboundEnv, EndpointConfig.create()),
                   is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer exchanged-access-token")));
        assertThat(response.requestHeaders().get(EXISTING_HEADER_NAME), is(List.of(EXISTING_HEADER_VALUE)));
        assertThat(REQUEST_COUNT.get(), is(1));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.method(), is("POST"));
        assertThat(request.authorization(),
                   is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
        assertThat(request.contentType(), is("application/x-www-form-urlencoded"));
        assertThat(request.formParameters(),
                   is(Map.of("grant_type", List.of(TOKEN_EXCHANGE_GRANT),
                             "requested_token_type", List.of(ACCESS_TOKEN_TYPE),
                             "subject_token", List.of(SUBJECT_TOKEN),
                             "subject_token_type", List.of(ACCESS_TOKEN_TYPE),
                             "scope", List.of("orders.read orders.write"),
                             "resource", List.of("https://orders.example.com"),
                             "audience", List.of("api://orders"))));
    }

    @Test
    void tokenExchangeCanUseWellKnownMetadataTokenEndpoint() {
        OidcProvider provider = provider(confidentialTenantFromWellKnown(), tokenExchangeTarget());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer exchanged-access-token")));
        assertThat(METADATA_REQUEST_COUNT.get(), is(1));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void endpointPolicyReusesWellKnownMetadataAndCachedToken() {
        OidcProvider provider = endpointPolicyProvider(confidentialTenantFromWellKnown());
        EndpointConfig endpointConfig = tokenExchangeEndpointConfig();

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                   outboundEnvironment(),
                                                                   endpointConfig);
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                    outboundEnvironment(),
                                                                    endpointConfig);

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer exchanged-access-token")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer exchanged-access-token")));
        assertThat(METADATA_REQUEST_COUNT.get(), is(1));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void tokenExchangeAbstainsWhenCurrentSubjectTokenIsMissing() {
        OidcProvider provider = provider(confidentialTenant(), tokenExchangeTarget());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void tokenExchangeCacheSeparatesSubjectTokens() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = 600;
        OidcProvider provider = provider(confidentialTenant(), tokenExchangeTarget());

        OutboundSecurityResponse firstSubject = provider.outboundSecurity(providerRequest("subject-token-1"),
                                                                          outboundEnvironment(),
                                                                          EndpointConfig.create());
        OutboundSecurityResponse secondSubject = provider.outboundSecurity(providerRequest("subject-token-2"),
                                                                           outboundEnvironment(),
                                                                           EndpointConfig.create());
        OutboundSecurityResponse firstSubjectAgain = provider.outboundSecurity(providerRequest("subject-token-1"),
                                                                               outboundEnvironment(),
                                                                               EndpointConfig.create());

        assertThat(firstSubject.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer exchanged-access-token-1")));
        assertThat(secondSubject.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer exchanged-access-token-2")));
        assertThat(firstSubjectAgain.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer exchanged-access-token-1")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void concurrentTokenExchangeRequestsUseSingleTokenEndpointRequest() throws Exception {
        int taskCount = 32;
        dynamicTokenResponse = true;
        dynamicExpiresIn = 600;
        tokenRequestStarted = new CountDownLatch(1);
        releaseTokenResponse = new CountDownLatch(1);
        CountDownLatch start = new CountDownLatch(1);
        OidcProvider provider = provider(confidentialTenant(), tokenExchangeTarget());

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<OutboundSecurityResponse>> futures = new ArrayList<>(taskCount);
            for (int i = 0; i < taskCount; i++) {
                futures.add(executor.submit(() -> {
                    assertThat(start.await(5, TimeUnit.SECONDS), is(true));
                    return provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                     outboundEnvironment(),
                                                     EndpointConfig.create());
                }));
            }

            start.countDown();
            assertThat(tokenRequestStarted.await(5, TimeUnit.SECONDS), is(true));
            releaseTokenResponse.countDown();
            for (Future<OutboundSecurityResponse> future : futures) {
                assertThat(future.get().requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                           is(List.of("Bearer exchanged-access-token-1")));
            }
        } finally {
            releaseTokenResponse.countDown();
        }

        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void highCardinalityTokenExchangeFloodIsBoundedAndRecovers() throws Exception {
        int taskCount = 1_000;
        int maxConcurrent = 4;
        int maxQueued = 8;
        dynamicTokenResponse = true;
        dynamicExpiresIn = 600;
        tokenRequestStarted = new CountDownLatch(maxConcurrent);
        releaseTokenResponse = new CountDownLatch(1);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch overloadObserved = new CountDownLatch(1);
        // This cohort must reach Token Exchange admission rather than be rejected during tenant initialization.
        OidcTenantConfig tenant = OidcTenantConfig.builder(confidentialTenantFromWellKnown())
                .initializationMaxQueued(taskCount)
                .tokenExchangeRemoteWork(remoteWork -> remoteWork
                        .maxConcurrent(maxConcurrent)
                        .maxQueued(maxQueued)
                        .admissionTimeout(Duration.ofMillis(100)))
                .buildPrototype();
        OidcProvider provider = endpointPolicyProvider(tenant);
        EndpointConfig endpointConfig = tokenExchangeEndpointConfig();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<OutboundSecurityResponse>> futures = new ArrayList<>(taskCount);
            for (int i = 0; i < taskCount; i++) {
                String token = "subject-token-" + i;
                futures.add(executor.submit(() -> {
                    assertThat(start.await(5, TimeUnit.SECONDS), is(true));
                    OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(token),
                                                                                  outboundEnvironment(),
                                                                                  endpointConfig);
                    if (response.status() == SecurityResponse.SecurityStatus.FAILURE) {
                        overloadObserved.countDown();
                    }
                    return response;
                }));
            }

            start.countDown();
            assertThat(tokenRequestStarted.await(5, TimeUnit.SECONDS), is(true));
            assertThat(overloadObserved.await(5, TimeUnit.SECONDS), is(true));
            releaseTokenResponse.countDown();

            int succeeded = 0;
            int overloaded = 0;
            for (Future<OutboundSecurityResponse> future : futures) {
                OutboundSecurityResponse response = future.get(10, TimeUnit.SECONDS);
                if (response.status() == SecurityResponse.SecurityStatus.SUCCESS) {
                    succeeded++;
                } else if (response.status() == SecurityResponse.SecurityStatus.FAILURE) {
                    overloaded++;
                    assertThat(response.description().orElse(""), is("Token Exchange failed"));
                }
            }
            assertThat(succeeded + overloaded, is(taskCount));
            assertThat(overloaded > 0, is(true));
            assertThat(MAX_ACTIVE_REQUESTS.get() <= maxConcurrent, is(true));
            assertThat(REQUEST_COUNT.get(), is(succeeded));
        } finally {
            releaseTokenResponse.countDown();
        }

        OutboundSecurityResponse recovered = provider.outboundSecurity(providerRequest("recovery-token"),
                                                                       outboundEnvironment(),
                                                                       endpointConfig);
        assertThat(recovered.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(METADATA_REQUEST_COUNT.get(), is(1));
        assertThat(ACTIVE_REQUESTS.get(), is(0));
    }

    @Test
    void tokenExchangeRejectsUnusableLifetimesWithoutCaching() {
        int expectedRequests = 0;
        for (String lifetime : List.of("0", "-1", "1.5", "9223372036854775808")) {
            responseBody = JsonObject.builder()
                    .from(tokenExchangeResponse("unusable-access-token", null))
                    .set("expires_in", new BigDecimal(lifetime))
                    .build()
                    .toString();
            OidcProvider provider = provider(confidentialTenant(), tokenExchangeTarget());

            for (int i = 0; i < 2; i++) {
                OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                              outboundEnvironment(),
                                                                              EndpointConfig.create());

                assertThat("expires_in=" + lifetime, response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                assertThat(response.description().orElseThrow(), is("Token Exchange failed"));
                assertThat(response.requestHeaders().containsKey(HeaderNames.AUTHORIZATION.defaultCase()), is(false));
                assertThat(response.throwable().isEmpty(), is(true));
            }
            expectedRequests += 2;
            assertThat(REQUEST_COUNT.get(), is(expectedRequests));
        }
    }

    @Test
    void tokenExchangeCachesVeryLargeLifetimeWithoutOverflow() {
        responseBody = JsonObject.builder()
                .from(tokenExchangeResponse("exchanged-access-token", null))
                .set("expires_in", Long.MAX_VALUE)
                .build()
                .toString();
        OidcProvider provider = provider(confidentialTenant(), tokenExchangeTarget());

        for (int i = 0; i < 2; i++) {
            OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                          outboundEnvironment(),
                                                                          EndpointConfig.create());

            assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                       is(List.of("Bearer exchanged-access-token")));
        }
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void tokenExchangeDoesNotCacheTokenWithoutExpiresIn() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = null;
        OidcProvider provider = provider(confidentialTenant(), tokenExchangeTarget());

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                   outboundEnvironment(),
                                                                   EndpointConfig.create());
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                    outboundEnvironment(),
                                                                    EndpointConfig.create());

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer exchanged-access-token-1")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer exchanged-access-token-2")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void tokenExchangeDoesNotCacheShortPositiveLifetimes() {
        dynamicTokenResponse = true;
        for (int lifetime : List.of(1, 60)) {
            dynamicExpiresIn = lifetime;
            OidcProvider provider = provider(confidentialTenant(), tokenExchangeTarget());
            int requestsBefore = REQUEST_COUNT.get();

            OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                       outboundEnvironment(),
                                                                       EndpointConfig.create());
            OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                        outboundEnvironment(),
                                                                        EndpointConfig.create());

            assertThat(first.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(second.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                       is(List.of("Bearer exchanged-access-token-" + (requestsBefore + 1))));
            assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                       is(List.of("Bearer exchanged-access-token-" + (requestsBefore + 2))));
            assertThat(REQUEST_COUNT.get(), is(requestsBefore + 2));
        }
    }

    @Test
    void tokenEndpointErrorMapsToTokenExchangeOutboundFailure() {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid_target")
                .set("error_description", "requested target is not allowed")
                .build()
                .toString();
        OidcProvider provider = provider(confidentialTenant(), tokenExchangeTarget());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), is("Token Exchange failed"));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void targetConfigurationCanSelectTokenExchange() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", CLIENT_ID),
                        Map.entry("tenants.default.client-secret", CLIENT_SECRET),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", tokenEndpointUri.toString()),
                        Map.entry("tenants.default.endpoints.tls-required", "false"),
                        Map.entry("outbound.0.name", "orders"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/orders/.*"),
                        Map.entry("outbound.0.methods.0", "GET"),
                        Map.entry("outbound.0.token-exchange-enabled", "true"),
                        Map.entry("outbound.0.token-exchange-scopes.0", "orders.read"),
                        Map.entry("outbound.0.token-exchange-resource", "https://orders.example.com"),
                        Map.entry("outbound.0.token-exchange-audience", "api://orders"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().formParameters().get("scope"), is(List.of("orders.read")));
        assertThat(RECORDED_REQUEST.get().formParameters().get("resource"), is(List.of("https://orders.example.com")));
        assertThat(RECORDED_REQUEST.get().formParameters().get("audience"), is(List.of("api://orders")));
    }

    @Test
    void tokenExchangeRequiresResourceOrAudience() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundPolicyConfig.builder()
                                                               .tokenExchangeEnabled(true)
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-exchange-resource or token-exchange-audience"));
    }

    @Test
    void tokenExchangeScopeWithoutTokenExchangeIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundPolicyConfig.builder()
                                                               .addTokenExchangeScope("orders.read")
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-exchange-enabled"));
    }

    @Test
    void invalidTokenExchangeResourceIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundPolicyConfig.builder()
                                                               .tokenExchangeEnabled(true)
                                                               .tokenExchangeResource("https://orders.example.com#read")
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-exchange-resource"));
    }

    @Test
    void paddedTokenExchangeAudienceIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundPolicyConfig.builder()
                                                               .tokenExchangeEnabled(true)
                                                               .tokenExchangeAudience(" api://orders")
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-exchange-audience"));
    }

    @Test
    void tokenExchangeIsMutuallyExclusiveWithOtherOutboundStrategies() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundPolicyConfig.builder()
                                                               .tokenExchangeEnabled(true)
                                                               .tokenExchangeAudience("api://orders")
                                                               .clientCredentialsGrantEnabled(true)
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("Only one OIDC outbound strategy"));
    }

    @Test
    void tokenExchangeRequiresConfidentialClient() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> provider(publicClientTenant(), tokenExchangeTarget()));

        assertThat(thrown.getMessage(), containsString("Token Endpoint authentication cannot be NONE"));
    }

    @Test
    void discoveredGrantTypesControlConfiguredAndDeferredTokenExchange() {
        JsonObject baseMetadata = JsonParser.create(providerMetadata).readJsonObject();
        List<Optional<List<String>>> grantLists = List.of(Optional.empty(),
                                                         Optional.of(List.of("authorization_code", "implicit")),
                                                         Optional.of(List.of()),
                                                         Optional.of(List.of("client_credentials")),
                                                         Optional.of(List.of(TOKEN_EXCHANGE_GRANT)),
                                                         Optional.of(List.of("authorization_code", "client_credentials",
                                                                             TOKEN_EXCHANGE_GRANT)));
        List<Executable> tests = new ArrayList<>();
        for (boolean endpointPolicy : List.of(false, true)) {
            for (Optional<List<String>> grants : grantLists) {
                tests.add(() -> {
                    String scenario = "endpointPolicy=" + endpointPolicy + " grants=" + grants;
                    JsonObject.Builder metadata = JsonObject.builder().from(baseMetadata).unset("grant_types_supported");
                    grants.ifPresent(values -> metadata.setStrings("grant_types_supported", values));
                    providerMetadata = metadata.build().toString();
                    METADATA_REQUEST_COUNT.set(0);
                    REQUEST_COUNT.set(0);
                    RECORDED_REQUEST.set(null);
                    boolean supported = grants.filter(values -> values.contains(TOKEN_EXCHANGE_GRANT)).isPresent();
                    SecurityResponse.SecurityStatus expectedStatus = supported
                            ? SecurityResponse.SecurityStatus.SUCCESS : SecurityResponse.SecurityStatus.FAILURE;
                    OidcTenantConfig tenant = confidentialTenantFromWellKnown();
                    EndpointConfig endpoint = endpointPolicy ? tokenExchangeEndpointConfig() : EndpointConfig.create();
                    try (OidcProvider provider = endpointPolicy
                            ? endpointPolicyProvider(tenant) : provider(tenant, tokenExchangeTarget())) {
                        for (int attempt = 0; attempt < 2; attempt++) {
                            OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                                        outboundEnvironment(), endpoint);
                            assertAll(() -> assertThat(scenario, response.status(), is(expectedStatus)),
                                      () -> assertThat(scenario, METADATA_REQUEST_COUNT.get(), is(1)),
                                      () -> assertThat(scenario, REQUEST_COUNT.get(), is(supported ? 1 : 0)));
                            if (supported) {
                                assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                                           is(List.of("Bearer exchanged-access-token")));
                            } else {
                                assertThat(response.requestHeaders().containsKey(HeaderNames.AUTHORIZATION.defaultCase()),
                                           is(false));
                                assertThat(response.description().orElseThrow(), is(endpointPolicy
                                        ? "Token Exchange failed" : "OIDC tenant is unavailable"));
                            }
                        }
                        assertThat(provider.tenantRuntimeRegistry().tenantContext("default").orElseThrow().ready(),
                                   is(endpointPolicy || supported));
                    }
                });
            }
        }
        assertAll(tests);
    }

    @Test
    void staticTokenExchangeDoesNotRequireDiscoveryGrantMetadata() {
        metadataResponseStatus = 503;
        providerMetadata = "unavailable discovery must not be contacted";
        OidcTenantConfig tenant = OidcTenantConfig.builder(confidentialTenant()).issuer(issuer.toString()).buildPrototype();
        for (boolean endpointPolicy : List.of(false, true)) {
            REQUEST_COUNT.set(0);
            EndpointConfig endpoint = endpointPolicy ? tokenExchangeEndpointConfig() : EndpointConfig.create();
            try (OidcProvider provider = endpointPolicy
                    ? endpointPolicyProvider(tenant) : provider(tenant, tokenExchangeTarget())) {
                for (int attempt = 0; attempt < 2; attempt++) {
                    OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(SUBJECT_TOKEN),
                                                                                  outboundEnvironment(), endpoint);
                    assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                    assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                               is(List.of("Bearer exchanged-access-token")));
                }
                assertThat(METADATA_REQUEST_COUNT.get(), is(0));
                assertThat(REQUEST_COUNT.get(), is(1));
            }
        }
    }

    @Test
    void tokenExchangeResponseRejectsUnsupportedIssuedTokenType() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTokenExchangeResponse.fromJson(JsonObject.builder()
                                                               .set("access_token", "issued-token")
                                                               .set("issued_token_type",
                                                                    "urn:ietf:params:oauth:token-type:id_token")
                                                               .set("token_type", "Bearer")
                                                               .build()));

        assertThat(thrown.getMessage(), containsString("issued_token_type"));
    }

    @Test
    void tokenExchangeResponseRejectsNaTokenType() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTokenExchangeResponse.fromJson(JsonObject.builder()
                                                               .set("access_token", "issued-token")
                                                               .set("issued_token_type", ACCESS_TOKEN_TYPE)
                                                               .set("token_type", "N_A")
                                                               .build()));

        assertThat(thrown.getMessage(), containsString("token_type"));
    }

    private static void handleTokenEndpoint(ServerRequest request, ServerResponse response) {
        int requestNumber = REQUEST_COUNT.incrementAndGet();
        int active = ACTIVE_REQUESTS.incrementAndGet();
        MAX_ACTIVE_REQUESTS.accumulateAndGet(active, Math::max);
        try {
            CountDownLatch requestStarted = tokenRequestStarted;
            if (requestStarted != null) {
                requestStarted.countDown();
            }
            CountDownLatch releaseResponse = releaseTokenResponse;
            if (releaseResponse != null) {
                await(releaseResponse);
            }
            RECORDED_REQUEST.set(new RecordedRequest(request.prologue().method().text(),
                                                    request.headers().first(HeaderNames.AUTHORIZATION).orElse(""),
                                                    request.headers().first(HeaderNames.CONTENT_TYPE).orElse(""),
                                                    formParameters(request.content().as(Parameters.class))));
            String body = dynamicTokenResponse
                    ? tokenExchangeResponse("exchanged-access-token-" + requestNumber, dynamicExpiresIn).toString()
                    : responseBody;
            response.status(responseStatus)
                    .header(HeaderValues.CONTENT_TYPE_JSON)
                    .header(HeaderNames.CACHE_CONTROL, "no-store")
                    .header(HeaderNames.PRAGMA, "no-cache")
                    .send(body);
        } finally {
            ACTIVE_REQUESTS.decrementAndGet();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            assertThat(latch.await(5, TimeUnit.SECONDS), is(true));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for Token Endpoint test response", e);
        }
    }

    private static OidcProvider provider(OidcTenantConfig tenant, OutboundTarget... outboundTargets) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .outboundTargets(List.of(outboundTargets))
                                           .buildPrototype());
    }

    private static OidcProvider endpointPolicyProvider(OidcTenantConfig tenant) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .buildPrototype());
    }

    private static EndpointConfig clientCredentialsEndpointConfig(String scope) {
        return EndpointConfig.builder().customObject(OidcOutboundPolicyConfig.class,
                OidcOutboundPolicyConfig.builder().clientCredentialsGrantEnabled(true)
                        .addClientCredentialsScope(scope).buildPrototype()).build();
    }

    private static void awaitActive(OidcRemoteWorkLimiter limiter, int count) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (limiter.activeCount() != count && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        assertThat(limiter.activeCount(), is(count));
    }

    private static EndpointConfig tokenExchangeEndpointConfig() {
        return EndpointConfig.builder()
                .customObject(OidcOutboundPolicyConfig.class,
                              OidcOutboundPolicyConfig.builder()
                                      .tokenExchangeEnabled(true)
                                      .addTokenExchangeScope("orders.read")
                                      .addTokenExchangeScope("orders.write")
                                      .tokenExchangeResource("https://orders.example.com")
                                      .tokenExchangeAudience("api://orders")
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget tokenExchangeTarget() {
        return OutboundTarget.builder("orders")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/orders/.*")
                .addMethod("GET")
                .customObject(OidcOutboundPolicyConfig.class,
                              OidcOutboundPolicyConfig.builder()
                                      .tokenExchangeEnabled(true)
                                      .addTokenExchangeScope("orders.read")
                                      .addTokenExchangeScope("orders.write")
                                      .tokenExchangeResource("https://orders.example.com")
                                      .tokenExchangeAudience("api://orders")
                                      .buildPrototype())
                .build();
    }

    private static SecurityEnvironment outboundEnvironment() {
        URI uri = URI.create("https://api.example.com/orders/42");
        return SecurityEnvironment.builder()
                .targetUri(uri)
                .transport(uri.getScheme())
                .path("/orders/42")
                .method("GET")
                .header(EXISTING_HEADER_NAME, EXISTING_HEADER_VALUE)
                .build();
    }

    private static ProviderRequest providerRequest() {
        return OidcProviderTest.request(null, SecurityEnvironment.create());
    }

    private static ProviderRequest providerRequest(String token) {
        TokenCredential credential = TokenCredential.builder()
                .token(token)
                .build();
        Subject subject = Subject.builder()
                .principal(Principal.create("user1"))
                .addPublicCredential(TokenCredential.class, credential)
                .build();
        return new TestProviderRequest(subject);
    }

    private static JsonObject tokenExchangeResponse(String accessToken, Integer expiresIn) {
        JsonObject.Builder builder = JsonObject.builder()
                .set("access_token", accessToken)
                .set("issued_token_type", ACCESS_TOKEN_TYPE)
                .set("token_type", "Bearer");
        if (expiresIn != null) {
            builder.set("expires_in", expiresIn);
        }
        return builder.build();
    }

    private static Map<String, List<String>> formParameters(Parameters parameters) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (String name : parameters.names()) {
            result.put(name, parameters.all(name));
        }
        return result;
    }

    private OidcTenantConfig confidentialTenant() {
        return OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .buildPrototype();
    }

    private OidcTenantConfig confidentialTenantFromWellKnown() {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
    }

    private OidcTenantConfig publicClientTenant() {
        return OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.NONE)
                .endpoints(it -> it.tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .buildPrototype();
    }

    private record RecordedRequest(String method,
                                   String authorization,
                                   String contentType,
                                   Map<String, List<String>> formParameters) {
    }

    private static final class TestProviderRequest implements ProviderRequest {
        private final Subject subject;

        private TestProviderRequest(Subject subject) {
            this.subject = subject;
        }

        @Override
        public EndpointConfig endpointConfig() {
            return EndpointConfig.create();
        }

        @Override
        public SecurityContext securityContext() {
            return null;
        }

        @Override
        public Optional<Subject> subject() {
            return Optional.of(subject);
        }

        @Override
        public Optional<Subject> service() {
            return Optional.empty();
        }

        @Override
        public SecurityEnvironment env() {
            return SecurityEnvironment.create();
        }

        @Override
        public Optional<Object> getObject() {
            return Optional.empty();
        }

        @Override
        public Object abacAttributeRaw(String key) {
            return null;
        }

        @Override
        public Collection<String> abacAttributeNames() {
            return List.of();
        }
    }
}
