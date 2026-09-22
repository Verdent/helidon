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

package io.helidon.tests.integration.security.oidcnext;

import java.net.URI;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.http.HeaderNames;
import io.helidon.http.HttpMediaTypes;
import io.helidon.http.Status;
import io.helidon.security.Security;
import io.helidon.security.providers.common.OutboundConfig;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.oidc.next.OidcOutboundTargetConfig;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcRequest;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webclient.security.WebClientSecurity;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.security.SecurityFeature;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcOutboundFlowIT {
    private static final String CLIENT_ID = "service-client";
    private static final String CLIENT_SECRET = "service-secret";
    private static final String INBOUND_AUDIENCE = "api://rp";
    private static final String DOWNSTREAM_AUDIENCE = "api://orders";
    private static final String DOWNSTREAM_RESOURCE = "https://orders.example.com";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    @Test
    void clientCredentialsOverloadAddsNoCredentialAndRecoversThroughWebClient() throws Exception {
        CountDownLatch tokenEntered = new CountDownLatch(1);
        CountDownLatch releaseToken = new CountDownLatch(1);
        AtomicInteger authenticatedDownstream = new AtomicInteger();
        AtomicReference<String> downstreamAuthorization = new AtomicReference<>();
        WebServer downstream = WebServer.builder().port(0).routing(routing -> routing.get("/orders/42", (request, response) -> {
            String authorization = request.headers().first(HeaderNames.AUTHORIZATION).orElse("");
            if (!authorization.startsWith("Bearer ")) {
                response.status(Status.UNAUTHORIZED_401).send("Bearer token required");
                return;
            }
            authenticatedDownstream.incrementAndGet();
            downstreamAuthorization.set(authorization);
            response.send("downstream");
        })).build().start();
        try (TestOidcServer idp = idp(INBOUND_AUDIENCE).allowedScopes("orders.read")
                .endpoints(endpoints -> endpoints.token(context -> {
                    if (context.request().formParam("scope").filter("orders.read"::equals).isPresent()) {
                        tokenEntered.countDown();
                        try {
                            if (!releaseToken.await(10, TimeUnit.SECONDS)) {
                                throw new IllegalStateException("Test did not release the Token Endpoint");
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException(e);
                        }
                    }
                    context.sendDefault();
                })).build()) {
            String inboundToken = OidcIntegrationSupport.clientCredentialsToken(idp, CLIENT_ID, CLIENT_SECRET);
            OidcProviderConfig config = protectedResourceProviderConfig(idp, clientCredentialsTarget(),
                    tenant -> tenant.clientCredentialsRemoteWork(work -> work.maxConcurrent(1).maxQueued(0)));
            WebServer rp = proxyServer(config, downstream);
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                try {
                    Future<?> leader = executor.submit(() -> callProxy(rp, inboundToken));
                    assertThat(tokenEntered.await(5, TimeUnit.SECONDS), is(true));
                    executor.submit(() -> {
                        WebClient client = WebClient.builder().baseUri(OidcIntegrationSupport.rpBaseUri(rp)).build();
                        try {
                            try (HttpClientResponse response = client.get("/proxy")
                                    .header(HeaderNames.AUTHORIZATION, "Bearer " + inboundToken).request()) {
                                // WebClientSecurity currently proceeds on provider FAILURE; the protected resource must reject
                                // the missing credential. This check also permits a future fail-closed client integration.
                                assertThat(response.status().family(), not(Status.Family.SUCCESSFUL));
                            }
                        } finally {
                            client.closeResource();
                        }
                    }).get(2, TimeUnit.SECONDS);
                    assertThat(authenticatedDownstream.get(), is(0));
                    assertThat(idp.tokenRequests().size(), is(2)); // Inbound setup token plus one active outbound grant.
                    assertThat(leader.isDone(), is(false));
                    releaseToken.countDown();
                    leader.get(5, TimeUnit.SECONDS);
                    assertThat(authenticatedDownstream.get(), is(1));
                    assertThat(downstreamAuthorization.get(), not("Bearer " + inboundToken));
                    callProxy(rp, inboundToken);
                    assertThat(authenticatedDownstream.get(), is(2));
                    assertThat(idp.tokenRequests().size(), is(2));
                } finally {
                    releaseToken.countDown();
                    rp.stop();
                }
            }
        } finally {
            releaseToken.countDown();
            downstream.stop();
        }
    }

    @Test
    void outboundTargetPropagatesCurrentBearerTokenThroughWebClient() {
        AtomicReference<String> downstreamAuthorization = new AtomicReference<>();
        WebServer downstream = downstream(downstreamAuthorization);
        try (TestOidcServer idp = idp(INBOUND_AUDIENCE).build()) {
            String accessToken = OidcIntegrationSupport.clientCredentialsToken(idp, CLIENT_ID, CLIENT_SECRET);
            OidcProviderConfig providerConfig = protectedResourceProviderConfig(idp,
                                                                                tokenPropagationTarget(INBOUND_AUDIENCE));
            WebServer rpServer = proxyServer(providerConfig, downstream);
            try {
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);
                WebClient client = WebClient.builder()
                        .baseUri(rpBaseUri)
                        .build();
                try {
                    try (HttpClientResponse response = client.get("/proxy")
                            .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                            .request()) {
                        assertThat(response.status(), is(Status.OK_200));
                        assertThat(response.as(String.class), is("downstream"));
                    }
                } finally {
                    client.closeResource();
                }

                assertThat(downstreamAuthorization.get(), is("Bearer " + accessToken));
            } finally {
                rpServer.stop();
            }
        } finally {
            downstream.stop();
        }
    }

    @Test
    void outboundTargetObtainsClientCredentialsTokenThroughWebClient() {
        AtomicReference<String> downstreamAuthorization = new AtomicReference<>();
        WebServer downstream = downstream(downstreamAuthorization);
        try (TestOidcServer idp = idp(INBOUND_AUDIENCE)
                .allowedScopes("orders.read")
                .build()) {
            String inboundToken = OidcIntegrationSupport.clientCredentialsToken(idp, CLIENT_ID, CLIENT_SECRET);
            OidcProviderConfig providerConfig = protectedResourceProviderConfig(idp,
                                                                                clientCredentialsTarget());
            WebServer rpServer = proxyServer(providerConfig, downstream);
            try {
                callProxy(rpServer, inboundToken);

                assertThat(downstreamAuthorization.get(), not("Bearer " + inboundToken));
                assertThat(downstreamAuthorization.get().startsWith("Bearer "), is(true));
                TestOidcRequest outboundTokenRequest = idp.tokenRequests().get(1);
                assertThat(outboundTokenRequest.formParam("grant_type").orElse(""), is("client_credentials"));
                assertThat(outboundTokenRequest.formParam("scope").orElse(""), is("orders.read"));
                assertThat(outboundTokenRequest.formParameters().get("resource"), is(List.of(DOWNSTREAM_RESOURCE)));
            } finally {
                rpServer.stop();
            }
        } finally {
            downstream.stop();
        }
    }

    @Test
    @Timeout(10)
    void providerOwnedTrafficBypassesConfiguredWebClientSecurity() {
        AtomicReference<String> downstreamAuthorization = new AtomicReference<>();
        AtomicInteger internalRequests = new AtomicInteger();
        AtomicInteger outboundSecurityInvocations = new AtomicInteger();
        WebServer downstream = downstream(downstreamAuthorization);
        try (TestOidcServer idp = idp(INBOUND_AUDIENCE)
                .allowedScopes("orders.read")
                .build()) {
            String inboundToken = OidcIntegrationSupport.clientCredentialsToken(idp, CLIENT_ID, CLIENT_SECRET);
            Security rejectingOutboundSecurity = Security.builder()
                    .addOutboundSecurityProvider((_, _, _) -> {
                        outboundSecurityInvocations.incrementAndGet();
                        throw new AssertionError("provider-owned traffic entered outbound security");
                    })
                    .build();
            WebClientConfig internalWebClient = WebClientConfig.builder()
                    .servicesDiscoverServices(false)
                    .addService((chain, request) -> {
                        internalRequests.incrementAndGet();
                        assertThat(request.properties().get(OutboundConfig.PROPERTY_DISABLE_OUTBOUND),
                                   is(Boolean.TRUE.toString()));
                        return chain.proceed(request);
                    })
                    .addService(WebClientSecurity.create(rejectingOutboundSecurity))
                    .buildPrototype();
            OidcProviderConfig providerConfig = wellKnownProtectedResourceProviderConfig(
                    idp,
                    clientCredentialsTarget(),
                    internalWebClient);
            WebServer rpServer = proxyServer(providerConfig, downstream);
            try {
                callProxy(rpServer, inboundToken);

                assertThat(internalRequests.get(), is(3));
                assertThat(outboundSecurityInvocations.get(), is(0));
                assertThat(idp.tokenRequests().get(1).formParam("grant_type").orElse(""),
                           is("client_credentials"));
            } finally {
                rpServer.stop();
            }
        } finally {
            downstream.stop();
        }
    }

    @Test
    void outboundTargetExchangesCurrentBearerTokenThroughWebClient() {
        AtomicReference<String> downstreamAuthorization = new AtomicReference<>();
        WebServer downstream = downstream(downstreamAuthorization);
        try (TestOidcServer idp = idp(INBOUND_AUDIENCE)
                .allowedScopes("orders.read")
                .build()) {
            String inboundToken = OidcIntegrationSupport.clientCredentialsToken(idp, CLIENT_ID, CLIENT_SECRET);
            OidcProviderConfig providerConfig = protectedResourceProviderConfig(idp, tokenExchangeTarget());
            WebServer rpServer = proxyServer(providerConfig, downstream);
            try {
                callProxy(rpServer, inboundToken);

                assertThat(downstreamAuthorization.get(), not("Bearer " + inboundToken));
                assertThat(downstreamAuthorization.get().startsWith("Bearer "), is(true));
                TestOidcRequest tokenExchangeRequest = idp.tokenRequests().get(1);
                assertThat(tokenExchangeRequest.formParam("grant_type").orElse(""),
                           is("urn:ietf:params:oauth:grant-type:token-exchange"));
                assertThat(tokenExchangeRequest.formParam("requested_token_type").orElse(""), is(ACCESS_TOKEN_TYPE));
                assertThat(tokenExchangeRequest.formParam("subject_token").orElse(""), is(inboundToken));
                assertThat(tokenExchangeRequest.formParam("subject_token_type").orElse(""), is(ACCESS_TOKEN_TYPE));
                assertThat(tokenExchangeRequest.formParam("scope").orElse(""), is("orders.read"));
                assertThat(tokenExchangeRequest.formParam("resource").orElse(""), is(DOWNSTREAM_RESOURCE));
                assertThat(tokenExchangeRequest.formParam("audience").orElse(""), is(DOWNSTREAM_AUDIENCE));
            } finally {
                rpServer.stop();
            }
        } finally {
            downstream.stop();
        }
    }

    private static WebServer downstream(AtomicReference<String> authorization) {
        return WebServer.builder()
                .port(0)
                .routing(routing -> routing.get("/orders/42", (request, response) -> {
                    authorization.set(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""));
                    response.headers().contentType(HttpMediaTypes.PLAINTEXT_UTF_8);
                    response.send("downstream");
                }))
                .build()
                .start();
    }

    private static TestOidcServer.Builder idp(String audience) {
        return TestOidcServer.builder()
                .client(CLIENT_ID, CLIENT_SECRET)
                .defaultScopes("service.read")
                .tokenDefaults(tokens -> tokens.accessToken(accessToken -> accessToken.audience(audience)));
    }

    private static OidcProviderConfig protectedResourceProviderConfig(TestOidcServer idp, OutboundTarget outboundTarget) {
        return protectedResourceProviderConfig(idp, outboundTarget, _ -> { });
    }

    private static OidcProviderConfig wellKnownProtectedResourceProviderConfig(TestOidcServer idp,
                                                                               OutboundTarget outboundTarget,
                                                                               WebClientConfig webClient) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(idp.issuer().toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(endpoints -> endpoints
                        .wellKnownUri(idp.metadataUri())
                        .tlsRequired(false))
                .webClient(webClient)
                .tokenTransport(transport -> transport.secureTransportRequired(false))
                .protectedResource(resource -> resource
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.JWT)
                                .audience(INBOUND_AUDIENCE)))
                .buildPrototype();
        return OidcProviderConfig.builder()
                .putTenant("default", tenant)
                .addOutboundTarget(outboundTarget)
                .buildPrototype();
    }

    private static OidcProviderConfig protectedResourceProviderConfig(TestOidcServer idp,
                                                                      OutboundTarget outboundTarget,
                                                                      Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(idp.issuer().toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(endpoints -> endpoints
                        .tokenEndpointUri(idp.tokenEndpointUri())
                        .jwksUri(idp.jwksUri())
                        .tlsRequired(false))
                .tokenTransport(transport -> transport.secureTransportRequired(false))
                .protectedResource(resource -> resource
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.JWT)
                                .audience(INBOUND_AUDIENCE)))
                .update(tenantCustomizer)
                .buildPrototype();
        return OidcProviderConfig.builder()
                .putTenant("default", tenant)
                .addOutboundTarget(outboundTarget)
                .buildPrototype();
    }

    private static OutboundTarget tokenPropagationTarget(String audience) {
        return outboundTarget("propagation")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .tokenPropagationEnabled(true)
                                      .audience(audience)
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget clientCredentialsTarget() {
        return outboundTarget("client-credentials")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .addClientCredentialsScope("orders.read")
                                      .addClientCredentialsResource(DOWNSTREAM_RESOURCE)
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget tokenExchangeTarget() {
        return outboundTarget("token-exchange")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .tokenExchangeEnabled(true)
                                      .addTokenExchangeScope("orders.read")
                                      .tokenExchangeResource(DOWNSTREAM_RESOURCE)
                                      .tokenExchangeAudience(DOWNSTREAM_AUDIENCE)
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget.Builder outboundTarget(String name) {
        return OutboundTarget.builder(name)
                .addTransport("http")
                .addHost("localhost")
                .addPath("/orders/.*")
                .addMethod("GET");
    }

    private static WebServer proxyServer(OidcProviderConfig providerConfig, WebServer downstream) {
        URI downstreamUri = URI.create("http://localhost:" + downstream.port() + "/orders/42");
        return OidcIntegrationSupport.rpServer(providerConfig,
                                               routing -> routing.get("/proxy",
                                                                      SecurityFeature.authenticate(),
                                                                      (request, response) -> {
                                                                          WebClient outbound =
                                                                                  OidcIntegrationSupport.outboundClient();
                                                                          try (HttpClientResponse downstreamResponse =
                                                                                       outbound.get()
                                                                                               .uri(downstreamUri)
                                                                                               .request()) {
                                                                              response.status(downstreamResponse.status())
                                                                                      .send(downstreamResponse
                                                                                                    .as(String.class));
                                                                          } finally {
                                                                              outbound.closeResource();
                                                                          }
                                                                      }));
    }

    private static void callProxy(WebServer rpServer, String accessToken) {
        WebClient client = WebClient.builder()
                .baseUri(OidcIntegrationSupport.rpBaseUri(rpServer))
                .build();
        try {
            try (HttpClientResponse response = client.get("/proxy")
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                    .request()) {
                assertThat(response.status(), is(Status.OK_200));
                assertThat(response.as(String.class), is("downstream"));
            }
        } finally {
            client.closeResource();
        }
    }
}
