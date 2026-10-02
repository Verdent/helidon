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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.pki.Keys;
import io.helidon.common.tls.Tls;
import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ServerTest
class OidcWellKnownMetadataLoadingTest {
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI HTTPS_ISSUER = URI.create("https://issuer.example");
    private static final String TENANT_WEBCLIENT_HEADER = "X-Tenant-WebClient";
    private static final String TENANT_WEBCLIENT_HEADER_VALUE = "configured";
    private static final HeaderName TENANT_WEBCLIENT_HEADER_NAME = HeaderNames.create(TENANT_WEBCLIENT_HEADER);
    private static final AtomicReference<String> PROVIDER_METADATA = new AtomicReference<>();
    private static final AtomicReference<String> WELL_KNOWN_WEBCLIENT_HEADER = new AtomicReference<>();
    private static final AtomicInteger WELL_KNOWN_REQUESTS = new AtomicInteger();
    private static final AtomicInteger REDIRECTED_WELL_KNOWN_REQUESTS = new AtomicInteger();
    private static final List<OidcClientAuthenticationMethod> JWT_AUTHENTICATION_METHODS =
            List.of(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT, OidcClientAuthenticationMethod.PRIVATE_KEY_JWT);

    private static volatile String redirectLocation;
    private static volatile String wellKnownContentType;
    private static volatile Status wellKnownStatus;

    private URI issuer;
    private URI authorizationEndpointUri;
    private URI tokenEndpointUri;
    private URI jwksUri;
    private URI introspectionEndpointUri;
    private URI userInfoEndpointUri;
    private URI endSessionEndpointUri;
    private URI pushedAuthorizationRequestEndpointUri;

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.get("/.well-known/openid-configuration", (request, response) -> {
            WELL_KNOWN_REQUESTS.incrementAndGet();
            WELL_KNOWN_WEBCLIENT_HEADER.set(request.headers().first(TENANT_WEBCLIENT_HEADER_NAME).orElse(""));
            if (redirectLocation != null) {
                response.status(Status.TEMPORARY_REDIRECT_307)
                        .header(HeaderNames.LOCATION, redirectLocation)
                        .send();
                return;
            }
            if (wellKnownContentType != null) {
                response.header(HeaderNames.CONTENT_TYPE, wellKnownContentType);
            }
            if (wellKnownStatus != null) {
                response.status(wellKnownStatus);
            }
            response.send(PROVIDER_METADATA.get());
        });
        routing.get("/redirected-openid-configuration", (_, response) -> {
            REDIRECTED_WELL_KNOWN_REQUESTS.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(PROVIDER_METADATA.get());
        });
        routing.get("/tenant/.well-known/openid-configuration", (_, response) -> {
            WELL_KNOWN_REQUESTS.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON).send(PROVIDER_METADATA.get());
        });
        routing.get("/.well-known/oauth-authorization-server/tenant", (_, response) -> {
            WELL_KNOWN_REQUESTS.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON).send(PROVIDER_METADATA.get());
        });
    }

    @BeforeEach
    void setUp(URI serverUri) {
        issuer = URI.create(serverUri.toString().substring(0, serverUri.toString().length() - 1));
        authorizationEndpointUri = serverUri.resolve("authorize");
        tokenEndpointUri = serverUri.resolve("token");
        jwksUri = serverUri.resolve("jwks");
        introspectionEndpointUri = serverUri.resolve("introspect");
        userInfoEndpointUri = serverUri.resolve("userinfo");
        endSessionEndpointUri = serverUri.resolve("logout");
        // Metadata is served over HTTP in this fixture; the advertised PAR URL must still be HTTPS.
        pushedAuthorizationRequestEndpointUri = HTTPS_ISSUER.resolve("par");
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .build()
                                      .toString());
        WELL_KNOWN_WEBCLIENT_HEADER.set("");
        WELL_KNOWN_REQUESTS.set(0);
        REDIRECTED_WELL_KNOWN_REQUESTS.set(0);
        redirectLocation = null;
        wellKnownContentType = "application/json";
        wellKnownStatus = null;
    }

    @Test
    void certificateBoundAccessTokenMetadataDependsOnValidationMode() {
        List<Executable> tests = new ArrayList<>();
        for (OidcTokenValidationMethod method : List.of(OidcTokenValidationMethod.JWT, OidcTokenValidationMethod.INTROSPECTION)) {
            for (OidcCertificateBoundAccessTokenMode mode : OidcCertificateBoundAccessTokenMode.values()) {
                for (String advertised : List.of("omitted", "false", "true")) {
                    tests.add(() -> {
                        JsonObject.Builder metadata = providerMetadataBuilder();
                        boolean supported = "true".equals(advertised);
                        if (!"omitted".equals(advertised)) {
                            metadata.set("tls_client_certificate_bound_access_tokens", supported);
                        }
                        PROVIDER_METADATA.set(metadata.build().toString());
                        int requests = WELL_KNOWN_REQUESTS.get();
                        OidcTenantConfig tenant = OidcTenantConfig.builder()
                                .issuer(issuer.toString()).clientId("client-id").clientSecret("client-secret")
                                .endpoints(endpoints -> endpoints.tlsRequired(false))
                                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                                        .method(method).audience("api://default")
                                        .certificateBoundAccessTokens(binding -> binding.mode(mode))))
                                .buildPrototype();
                        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                .putTenant("tenant", tenant).buildPrototype())) {
                            OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();
                            boolean ready = mode != OidcCertificateBoundAccessTokenMode.REQUIRED || supported;
                            assertThat(method + " " + mode + " advertised=" + advertised, context.ready(), is(ready));
                            assertThat(WELL_KNOWN_REQUESTS.get(), is(requests + 1));
                            if (ready) {
                                assertThat(context.metadata().tlsClientCertificateBoundAccessTokens(), is(supported));
                            } else {
                                assertThat(context.state(), is(OidcTenantState.FAILED));
                                assertThat(context.failureCause().orElseThrow().getMessage(),
                                           is("well-known metadata tls_client_certificate_bound_access_tokens must be true"));
                            }
                        }
                    });
                }
            }
        }
        assertAll(tests);
    }

    @Test
    void authorizationCodeTenantLoadsWellKnownMetadataEndpoints() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer.toString())));
        assertThat(context.metadata().wellKnownUri(), is(Optional.of(issuer.resolve("/.well-known/openid-configuration"))));
        assertThat(context.metadata().authorizationEndpointUri(), is(Optional.of(authorizationEndpointUri)));
        assertThat(context.metadata().tokenEndpointUri(), is(Optional.of(tokenEndpointUri)));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.of(jwksUri)));
        assertThat(context.metadata().introspectionEndpointUri(), is(Optional.of(introspectionEndpointUri)));
        assertThat(context.metadata().userInfoEndpointUri(), is(Optional.of(userInfoEndpointUri)));
        assertThat(context.metadata().endSessionEndpointUri(), is(Optional.of(endSessionEndpointUri)));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void metadataOnlyAuthorizationCodeTenantRejectsAnotherIssuersMetadata() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .set("issuer", HTTPS_ISSUER.toString())
                                      .build().toString());
        OidcTenantConfig tenant = metadataOnlyAuthorizationCodeTenant(
                issuer.resolve("/.well-known/openid-configuration"));

        OidcTenantContext context = tenantContext(tenant);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.retryableFailure(), is(false));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("well-known metadata issuer must match well-known-uri"));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void configuredIssuerCannotTrustMetadataFromDifferentWellKnownUrl() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .set("issuer", HTTPS_ISSUER.toString())
                                      .build().toString());
        OidcTenantConfig tenant = OidcTenantConfig.builder(metadataOnlyAuthorizationCodeTenant(
                issuer.resolve("/.well-known/openid-configuration")))
                .issuer(HTTPS_ISSUER.toString())
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenant);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.retryableFailure(), is(false));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("well-known metadata issuer must match well-known-uri"));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(0));
    }

    @Test
    void metadataOnlyAuthorizationCodeTenantAcceptsCanonicalOpenIdDiscovery() {
        OidcTenantConfig tenant = metadataOnlyAuthorizationCodeTenant(
                issuer.resolve("/.well-known/openid-configuration"));

        OidcTenantContext context = tenantContext(tenant);

        assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                   context.state(), is(OidcTenantState.READY));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer.toString())));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void pathIssuerAcceptsCanonicalOpenIdDiscovery() {
        URI pathIssuer = issuer.resolve("/tenant");
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .set("issuer", pathIssuer.toString())
                                      .build().toString());
        OidcTenantConfig tenant = metadataOnlyAuthorizationCodeTenant(
                issuer.resolve("/tenant/.well-known/openid-configuration"));

        OidcTenantContext context = tenantContext(tenant);

        assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                   context.state(), is(OidcTenantState.READY));
        assertThat(context.metadata().issuer(), is(Optional.of(pathIssuer.toString())));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void pathIssuerAcceptsCanonicalOauthMetadataDiscovery() {
        URI pathIssuer = issuer.resolve("/tenant");
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .set("issuer", pathIssuer.toString())
                                      .build().toString());
        OidcTenantConfig tenant = metadataOnlyAuthorizationCodeTenant(
                issuer.resolve("/.well-known/oauth-authorization-server/tenant"));

        OidcTenantContext context = tenantContext(tenant);

        assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                   context.state(), is(OidcTenantState.READY));
        assertThat(context.metadata().issuer(), is(Optional.of(pathIssuer.toString())));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void configuredPathIssuerAcceptsCanonicalOauthMetadataDiscovery() {
        URI pathIssuer = issuer.resolve("/tenant");
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .set("issuer", pathIssuer.toString())
                                      .build().toString());
        OidcTenantConfig tenant = OidcTenantConfig.builder(metadataOnlyAuthorizationCodeTenant(
                issuer.resolve("/.well-known/oauth-authorization-server/tenant")))
                .issuer(pathIssuer.toString())
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenant);

        assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                   context.state(), is(OidcTenantState.READY));
        assertThat(context.metadata().issuer(), is(Optional.of(pathIssuer.toString())));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void providerAndFeatureShareConcurrentTenantInitialization() throws Exception {
        CountDownLatch discoveryStarted = new CountDownLatch(1);
        CountDownLatch releaseDiscovery = new CountDownLatch(1);
        CountDownLatch requestsStarted = new CountDownLatch(16);
        AtomicInteger discoveries = new AtomicInteger();
        AtomicReference<String> metadata = new AtomicReference<>();
        WebServer metadataServer = WebServer.builder()
                .port(0)
                .routing(routing -> routing.get("/.well-known/openid-configuration", (_, response) -> {
                    if (discoveries.incrementAndGet() > 1) {
                        response.status(Status.SERVICE_UNAVAILABLE_503).send();
                        return;
                    }
                    discoveryStarted.countDown();
                    try {
                        assertThat(releaseDiscovery.await(10, TimeUnit.SECONDS), is(true));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException(e);
                    }
                    response.header(HeaderValues.CONTENT_TYPE_JSON).send(metadata.get());
                }))
                .build().start();
        try {
            URI discoveryIssuer = URI.create("http://localhost:" + metadataServer.port());
            metadata.set(authorizationCodeMetadataBuilder()
                                 .set("issuer", discoveryIssuer.toString())
                                 .build().toString());
            OidcTenantConfig tenant = OidcTenantConfig.builder()
                    .issuer(discoveryIssuer.toString())
                    .clientId("client-id")
                    .endpoints(endpoints -> endpoints.tlsRequired(false)
                            .wellKnownUri(discoveryIssuer.resolve("/.well-known/openid-configuration")))
                    .authorizationCode(code -> code.redirectionEndpointUri(URI.create("/oidc/callback")))
                    .cookies(cookies -> cookies.protection(protection -> protection.password("test-cookie-password")))
                    .buildPrototype();
            OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder().putTenant("tenant", tenant).buildPrototype());
            WebServer rp = WebServer.builder().port(0).addFeature(OidcFeature.create(provider)).build().start();
            WebClient client = WebClient.create();
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                URI callback = URI.create("http://localhost:" + rp.port() + "/oidc/callback");
                Instant now = Instant.now();
                String state = OidcAuthorizationState.create("tenant",
                        Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32])).value();
                SetCookie stateCookie = OidcCookieStateHandler.create("tenant", tenant)
                        .createAuthenticationRequestCookie(new OidcAuthenticationRequestState("tenant", state,
                                "nonce", "verifier", null, discoveryIssuer.toString(), URI.create("/resource"), callback,
                                now, now.plusSeconds(300)));
                List<Future<AuthenticationResponse>> requests = new ArrayList<>();
                for (int index = 0; index < 16; index++) {
                    requests.add(executor.submit(() -> {
                        requestsStarted.countDown();
                        return provider.authenticate(OidcProviderTest.request(OidcEndpointPolicy.protectedResource(),
                                SecurityEnvironment.create()));
                    }));
                }
                try {
                    assertThat(discoveryStarted.await(5, TimeUnit.SECONDS), is(true));
                    Future<String> returned = executor.submit(() -> {
                        try (HttpClientResponse response = client.get().uri(callback)
                                .queryParam("error", "access_denied").queryParam("state", state)
                                .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value()).request()) {
                            assertThat(response.status(), is(Status.BAD_REQUEST_400));
                            return response.as(String.class);
                        }
                    });
                    assertThat(requestsStarted.await(5, TimeUnit.SECONDS), is(true));
                    releaseDiscovery.countDown();
                    for (Future<AuthenticationResponse> request : requests) {
                        assertThat(request.get(10, TimeUnit.SECONDS).statusCode().orElseThrow(), is(401));
                    }
                    assertThat(returned.get(10, TimeUnit.SECONDS),
                               is("OpenID Provider returned an Authorization Error Response"));
                    assertThat(discoveries.get(), is(1));
                } finally {
                    releaseDiscovery.countDown();
                }
            } finally {
                releaseDiscovery.countDown();
                client.closeResource();
                rp.stop();
            }
        } finally {
            releaseDiscovery.countDown();
            metadataServer.stop();
        }
    }

    @Test
    void sharedMultiIssuerCallbackRequiresIssuerResponseMetadataSupport() {
        OidcTenantConfig tenantConfig = authorizationCodeTenantConfig();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                multiIssuerProviderConfig(tenantConfig, REDIRECTION_ENDPOINT_URI));

        OidcTenantContext context = registry.tenantContext("tenant").orElseThrow();

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   is("well-known metadata authorization_response_iss_parameter_supported must be true when distinct "
                              + "authorization servers share a redirection endpoint"));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void sharedMultiIssuerCallbackAcceptsIssuerResponseMetadataSupport() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("authorization_response_iss_parameter_supported", true)
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = authorizationCodeTenantConfig();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                multiIssuerProviderConfig(tenantConfig, REDIRECTION_ENDPOINT_URI));

        OidcTenantContext context = registry.tenantContext("tenant").orElseThrow();

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().authorizationResponseIssuerParameterSupported(), is(true));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void distinctMultiIssuerCallbacksDoNotRequireIssuerResponseMetadataSupport() {
        OidcTenantConfig tenantConfig = authorizationCodeTenantConfig();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                multiIssuerProviderConfig(tenantConfig, URI.create("https://rp.example/other/callback")));

        OidcTenantContext context = registry.tenantContext("tenant").orElseThrow();

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().authorizationResponseIssuerParameterSupported(), is(false));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void tenantRecoversFromTransientWellKnownFailureAfterRetryInterval() {
        MutableClock clock = MutableClock.create(Instant.parse("2026-09-15T00:00:00Z"));
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .initializationRetryInterval(Duration.ofSeconds(10))
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                providerConfig,
                OidcTenantContextFactory.create(false, false),
                clock);
        wellKnownStatus = Status.SERVICE_UNAVAILABLE_503;

        OidcTenantContext failed = registry.tenantContext("tenant").orElseThrow();
        assertThat(failed.state(), is(OidcTenantState.FAILED));
        assertThat(failed.retryableFailure(), is(true));
        assertThat(registry.tenantContext("tenant").orElseThrow(), sameInstance(failed));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
        wellKnownStatus = null;
        clock.advance(Duration.ofSeconds(9));
        assertThat(registry.tenantContext("tenant").orElseThrow(), sameInstance(failed));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
        clock.advance(Duration.ofSeconds(1));

        OidcTenantContext recovered = registry.tenantContext("tenant").orElseThrow();

        assertThat(recovered.state(), is(OidcTenantState.READY));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(2));
    }

    @Test
    void deterministicWellKnownIssuerMismatchRemainsFailed() {
        MutableClock clock = MutableClock.create(Instant.parse("2026-09-15T00:00:00Z"));
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("issuer", "https://other.example")
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .initializationRetryInterval(Duration.ofSeconds(10))
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                providerConfig,
                OidcTenantContextFactory.create(false, false),
                clock);

        OidcTenantContext failed = registry.tenantContext("tenant").orElseThrow();
        assertThat(failed.state(), is(OidcTenantState.FAILED));
        assertThat(failed.retryableFailure(), is(false));
        clock.advance(Duration.ofHours(1));

        assertThat(registry.tenantContext("tenant").orElseThrow(), sameInstance(failed));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void authorizationCodeTenantLoadsWellKnownMetadataIssuerWhenEndpointsAreStatic() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.wellKnownUri(issuer.resolve("/.well-known/openid-configuration"))
                        .authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer.toString())));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void authorizationCodeTenantLoadsWellKnownPushedAuthorizationRequestMetadata() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("pushed_authorization_request_endpoint",
                                           pushedAuthorizationRequestEndpointUri.toString())
                                      .build()
                                      .toString());

        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().pushedAuthorizationRequestEndpointUri(),
                   is(Optional.of(pushedAuthorizationRequestEndpointUri)));
    }

    @Test
    void authorizationCodeTenantRejectsHttpPushedAuthorizationRequestEndpointInMetadata() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("pushed_authorization_request_endpoint", issuer.resolve("par").toString())
                                      .build()
                                      .toString());

        // This fixture deliberately allows an HTTP discovery URL, but that exception does not apply to PAR.
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("pushed-authorization-request-endpoint-uri must use https"));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void authorizationCodeTenantLoadsWellKnownMutualTlsPushedAuthorizationRequestMetadata() {
        URI mutualTlsPushedAuthorizationRequestEndpointUri = URI.create("https://issuer.example/mtls-par");
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("pushed_authorization_request_endpoint",
                                           pushedAuthorizationRequestEndpointUri.toString())
                                      .set("mtls_endpoint_aliases", JsonObject.builder()
                                              .set("token_endpoint", "https://issuer.example/mtls-token")
                                              .set("pushed_authorization_request_endpoint",
                                                   mutualTlsPushedAuthorizationRequestEndpointUri.toString())
                                              .build())
                                      .build()
                                      .toString());

        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.failureCause().map(Throwable::getMessage).orElse("ready"), context.ready(), is(true));
        assertThat(context.metadata().mutualTlsPushedAuthorizationRequestEndpointUri(),
                   is(Optional.of(mutualTlsPushedAuthorizationRequestEndpointUri)));
    }

    @Test
    void authorizationCodeTenantDoesNotLoadWellKnownMetadataOnlyToDiscoverOptionalPushedAuthorizationRequests() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .jwksUri(jwksUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().pushedAuthorizationRequestEndpointUri(), is(Optional.empty()));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(0));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(""));
    }

    @Test
    void staticAuthorizationEndpointsDoNotBypassDiscoveryTlsWhenJwksIsMissing() {
        PROVIDER_METADATA.set(httpsAuthorizationCodeMetadataBuilder().build().toString());
        OidcTenantConfig tenant = staticHttpsAuthorizationCodeTenant(
                issuer.resolve("/.well-known/openid-configuration"), _ -> { }).buildPrototype();

        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenant).buildPrototype())) {
            OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();

            assertAll(() -> assertThat(context.state(), is(OidcTenantState.FAILED)),
                      () -> assertThat(context.retryableFailure(), is(false)),
                      () -> assertThat(context.failureCause().map(Throwable::getMessage).orElse(""),
                                       containsString("well-known-uri must use https")),
                      () -> assertThat(WELL_KNOWN_REQUESTS.get(), is(0)));
            assertThat(provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow(), sameInstance(context));
            assertThat(WELL_KNOWN_REQUESTS.get(), is(0));
        }
    }

    @Test
    void staticAuthorizationEndpointsDoNotBypassDiscoveryTlsWhenParIsRequired() {
        PROVIDER_METADATA.set(httpsAuthorizationCodeMetadataBuilder()
                                      .set("pushed_authorization_request_endpoint", HTTPS_ISSUER.resolve("par").toString())
                                      .build().toString());
        OidcTenantConfig tenant = staticHttpsAuthorizationCodeTenant(
                issuer.resolve("/.well-known/openid-configuration"),
                endpoints -> endpoints.jwksUri(HTTPS_ISSUER.resolve("jwks")))
                .authorizationCode(code -> code.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .pushedAuthorizationRequests(OidcPushedAuthorizationRequestMode.REQUIRED))
                .buildPrototype();

        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenant).buildPrototype())) {
            OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();

            assertAll(() -> assertThat(context.state(), is(OidcTenantState.FAILED)),
                      () -> assertThat(context.retryableFailure(), is(false)),
                      () -> assertThat(context.failureCause().map(Throwable::getMessage).orElse(""),
                                       containsString("well-known-uri must use https")),
                      () -> assertThat(WELL_KNOWN_REQUESTS.get(), is(0)));
        }
    }

    @Test
    void staticAuthorizationEndpointsAllowExplicitHttpDiscoveryOptOut() {
        PROVIDER_METADATA.set(httpsAuthorizationCodeMetadataBuilder()
                                      .set("issuer", issuer.toString())
                                      .build().toString());
        OidcTenantConfig tenant = staticHttpsAuthorizationCodeTenant(
                issuer.resolve("/.well-known/openid-configuration"), endpoints -> endpoints.tlsRequired(false))
                .issuer(issuer.toString())
                .buildPrototype();

        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenant).buildPrototype())) {
            OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();

            assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                       context.state(), is(OidcTenantState.READY));
            assertThat(context.metadata().jwkSetUri(), is(Optional.of(HTTPS_ISSUER.resolve("jwks"))));
            assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
        }
    }

    @Test
    void completeStaticMetadataDoesNotFetchInsecureUnusedDiscoveryUri() {
        OidcTenantConfig tenant = staticHttpsAuthorizationCodeTenant(
                issuer.resolve("/.well-known/openid-configuration"),
                endpoints -> endpoints.jwksUri(HTTPS_ISSUER.resolve("jwks")))
                .buildPrototype();

        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenant).buildPrototype())) {
            OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();

            assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                       context.state(), is(OidcTenantState.READY));
            assertThat(context.metadata().wellKnownMetadataLoaded(), is(false));
            assertThat(WELL_KNOWN_REQUESTS.get(), is(0));
        }
    }

    @Test
    void staticAuthorizationEndpointsAllowHttpsDiscovery() {
        AtomicInteger requests = new AtomicInteger();
        AtomicReference<String> metadata = new AtomicReference<>();
        Keys keys = Keys.builder()
                .keystore(store -> store.passphrase("password").keystore(Resource.create("server.p12")))
                .build();
        Tls tls = Tls.builder().privateKey(keys).privateKeyCertChain(keys).build();
        WebServer metadataServer = WebServer.builder().port(0).tls(tls)
                .routing(routing -> routing.get("/.well-known/openid-configuration", (_, response) -> {
                    requests.incrementAndGet();
                    response.header(HeaderValues.CONTENT_TYPE_JSON).send(metadata.get());
                }))
                .build().start();
        try {
            URI metadataIssuer = URI.create("https://localhost:" + metadataServer.port());
            metadata.set(httpsAuthorizationCodeMetadataBuilder()
                                 .set("issuer", metadataIssuer.toString())
                                 .build().toString());
            WebClientConfig client = WebClientConfig.builder()
                    .tls(clientTls -> clientTls.trust(trust -> trust.keystore(store -> store
                            .passphrase("password").trustStore(true).keystore(Resource.create("server.p12")))))
                    .buildPrototype();
            OidcTenantConfig tenant = staticHttpsAuthorizationCodeTenant(
                    metadataIssuer.resolve("/.well-known/openid-configuration"), _ -> { })
                    .issuer(metadataIssuer.toString())
                    .webClient(client)
                    .buildPrototype();

            try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                    .putTenant("tenant", tenant).buildPrototype())) {
                OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();

                assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                           context.state(), is(OidcTenantState.READY));
                assertThat(context.metadata().issuer(), is(Optional.of(metadataIssuer.toString())));
                assertThat(context.metadata().wellKnownMetadataLoaded(), is(true));
                assertThat(requests.get(), is(1));
            }
        } finally {
            metadataServer.stop();
        }
    }

    @Test
    void httpsMetadataCannotClaimDifferentIssuerWithDefaultTlsPolicy() {
        AtomicInteger requests = new AtomicInteger();
        AtomicReference<String> metadata = new AtomicReference<>();
        Keys keys = Keys.builder()
                .keystore(store -> store.passphrase("password").keystore(Resource.create("server.p12")))
                .build();
        Tls tls = Tls.builder().privateKey(keys).privateKeyCertChain(keys).build();
        WebServer metadataServer = WebServer.builder().port(0).tls(tls)
                .routing(routing -> routing.get("/.well-known/openid-configuration", (_, response) -> {
                    requests.incrementAndGet();
                    response.header(HeaderValues.CONTENT_TYPE_JSON).send(metadata.get());
                }))
                .build().start();
        try {
            URI metadataIssuer = URI.create("https://localhost:" + metadataServer.port());
            metadata.set(httpsAuthorizationCodeMetadataBuilder()
                                 .set("token_endpoint", metadataIssuer.resolve("attacker-token").toString())
                                 .set("authorization_response_iss_parameter_supported", true)
                                 .build().toString());
            WebClientConfig client = WebClientConfig.builder()
                    .tls(clientTls -> clientTls.trust(trust -> trust.keystore(store -> store
                            .passphrase("password").trustStore(true).keystore(Resource.create("server.p12")))))
                    .buildPrototype();
            OidcTenantConfig tenant = OidcTenantConfig.builder()
                    .clientId("client-id")
                    .clientSecret("client-secret")
                    .webClient(client)
                    .endpoints(endpoints -> endpoints.wellKnownUri(
                            metadataIssuer.resolve("/.well-known/openid-configuration")))
                    .authorizationCode(code -> code.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                    .cookies(cookies -> cookies.protection(protection -> protection.password("test-cookie-password")))
                    .buildPrototype();

            try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                    .putTenant("tenant", tenant).buildPrototype())) {
                OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();

                assertThat(context.state(), is(OidcTenantState.FAILED));
                assertThat(context.retryableFailure(), is(false));
                assertThat(context.failureCause().orElseThrow().getMessage(),
                           containsString("well-known metadata issuer must match well-known-uri"));
                assertThat(requests.get(), is(1));
            }
            OidcTenantConfig pinned = OidcTenantConfig.builder(tenant).issuer(HTTPS_ISSUER.toString()).buildPrototype();
            try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                    .putTenant("tenant", pinned).buildPrototype())) {
                OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();

                assertThat(context.state(), is(OidcTenantState.FAILED));
                assertThat(context.retryableFailure(), is(false));
                assertThat(context.failureCause().orElseThrow().getMessage(),
                           containsString("well-known metadata issuer must match well-known-uri"));
                assertThat(requests.get(), is(1));
            }
        } finally {
            metadataServer.stop();
        }
    }

    @Test
    void deferredDiscoveryRejectsHttpForConcurrentCallers() throws Exception {
        PROVIDER_METADATA.set(httpsAuthorizationCodeMetadataBuilder().build().toString());
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(HTTPS_ISSUER.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(endpoints -> endpoints.wellKnownUri(issuer.resolve("/.well-known/openid-configuration")))
                .buildPrototype();
        MutableClock clock = MutableClock.create(Instant.parse("2026-09-29T10:00:00Z"));
        OidcOutboundMetadataResolver resolver = new OidcOutboundMetadataResolver(clock);
        CountDownLatch start = new CountDownLatch(1);

        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenant).buildPrototype());
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();
            assertThat(context.ready(), is(true));
            assertThat(WELL_KNOWN_REQUESTS.get(), is(0));
            List<Future<IllegalArgumentException>> failures = new ArrayList<>();
            for (int i = 0; i < 16; i++) {
                failures.add(executor.submit(() -> {
                    assertThat(start.await(5, TimeUnit.SECONDS), is(true));
                    return assertThrows(IllegalArgumentException.class,
                                        () -> resolver.clientCredentialsEndpointClient(context));
                }));
            }
            start.countDown();
            for (Future<IllegalArgumentException> failure : failures) {
                assertThat(failure.get(10, TimeUnit.SECONDS).getMessage(), containsString("well-known-uri must use https"));
            }
            clock.advance(Duration.ofDays(1));
            assertThat(assertThrows(IllegalArgumentException.class,
                                    () -> resolver.tokenExchangeEndpointClient(context)).getMessage(),
                       containsString("well-known-uri must use https"));
            assertThat(WELL_KNOWN_REQUESTS.get(), is(0));
        } finally {
            start.countDown();
        }
    }

    @Test
    void authorizationCodeTenantLoadsWellKnownMetadataWhenStaticEndpointsLackJwkSource() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.of(jwksUri)));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void authorizationCodeTenantFailsInitializationWhenMetadataHasNoJwkSource() {
        PROVIDER_METADATA.set(JsonObject.builder()
                                      .set("issuer", issuer.toString())
                                      .set("authorization_endpoint", authorizationEndpointUri.toString())
                                      .set("token_endpoint", tokenEndpointUri.toString())
                                      .setStrings("response_types_supported", List.of("code"))
                                      .setStrings("grant_types_supported", List.of("authorization_code"))
                                      .setStrings("code_challenge_methods_supported", List.of("S256"))
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("none"))
                                      .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("jwks"));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataRequiresPushedAuthorizationRequestsAndDisabled() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("pushed_authorization_request_endpoint",
                                           pushedAuthorizationRequestEndpointUri.toString())
                                      .set("require_pushed_authorization_requests", true)
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .pushedAuthorizationRequests(OidcPushedAuthorizationRequestMode.DISABLED))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("require_pushed_authorization_requests"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataRequiresPushedAuthorizationRequestsWithoutEndpoint() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("require_pushed_authorization_requests", true)
                                      .build()
                                      .toString());

        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("pushed_authorization_request_endpoint"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataRequiresRequestObjectsAndDisabled() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("require_signed_request_object", true)
                                      .set("request_parameter_supported", true)
                                      .setStrings("request_object_signing_alg_values_supported", List.of("RS256"))
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .requestObject(requestObject -> requestObject.mode(OidcRequestObjectMode.DISABLED)))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("require_signed_request_object"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataRequiresRequestObjectsWithoutSigningKey() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("require_signed_request_object", true)
                                      .set("request_parameter_supported", true)
                                      .setStrings("request_object_signing_alg_values_supported", List.of("RS256"))
                                      .build()
                                      .toString());

        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("authorization-code.request-object.signing-jwk"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDoesNotSupportByValueRequestObjects() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .setStrings("request_object_signing_alg_values_supported", List.of("RS256"))
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .requestObject(requestObject -> requestObject.mode(OidcRequestObjectMode.REQUIRED)
                                .signingJwk(jwk -> jwk.resourcePath("oidc-next-sign-jwk.json"))
                                .signingKeyId("sign-rsa")
                                .signingAlgorithm("RS256")))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("request_parameter_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDoesNotSupportRequestObjectAlgorithm() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("request_parameter_supported", true)
                                      .setStrings("request_object_signing_alg_values_supported", List.of("ES256"))
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .requestObject(requestObject -> requestObject.mode(OidcRequestObjectMode.REQUIRED)
                                .signingJwk(jwk -> jwk.resourcePath("oidc-next-sign-jwk.json"))
                                .signingKeyId("sign-rsa")
                                .signingAlgorithm("RS256")))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("request_object_signing_alg_values_supported"));
    }

    @Test
    void authorizationCodeTenantAcceptsSupportedRequestObjectMetadata() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("request_parameter_supported", true)
                                      .setStrings("request_object_signing_alg_values_supported", List.of("RS256"))
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .requestObject(requestObject -> requestObject.mode(OidcRequestObjectMode.REQUIRED)
                                .signingJwk(jwk -> jwk.resourcePath("oidc-next-sign-jwk.json"))
                                .signingKeyId("sign-rsa")
                                .signingAlgorithm("RS256")))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.failureCause().map(Throwable::getMessage).orElse("ready"), context.ready(), is(true));
    }

    @Test
    void authorizationCodeTenantAcceptsEncryptedRequestObjectMetadata() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("request_parameter_supported", true)
                                      .setStrings("request_object_signing_alg_values_supported", List.of("RS256"))
                                      .setStrings("request_object_encryption_alg_values_supported",
                                                  List.of("RSA-OAEP-256"))
                                      .setStrings("request_object_encryption_enc_values_supported",
                                                  List.of("A128CBC-HS256"))
                                      .build()
                                      .toString());

        OidcTenantContext context = tenantContext(encryptedRequestObjectTenant());

        assertThat(context.failureCause().map(Throwable::getMessage).orElse("ready"), context.ready(), is(true));
    }

    @Test
    void authorizationCodeTenantAllowsAbsentOptionalRequestObjectEncryptionMetadata() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("request_parameter_supported", true)
                                      .setStrings("request_object_signing_alg_values_supported", List.of("RS256"))
                                      .build()
                                      .toString());

        OidcTenantContext context = tenantContext(encryptedRequestObjectTenant());

        assertThat(context.failureCause().map(Throwable::getMessage).orElse("ready"), context.ready(), is(true));
    }

    @Test
    void authorizationCodeTenantRejectsUnsupportedRequestObjectEncryptionMetadata() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("request_parameter_supported", true)
                                      .setStrings("request_object_signing_alg_values_supported", List.of("RS256"))
                                      .setStrings("request_object_encryption_alg_values_supported", List.of("RSA-OAEP"))
                                      .setStrings("request_object_encryption_enc_values_supported", List.of("A256GCM"))
                                      .build()
                                      .toString());

        OidcTenantContext context = tenantContext(encryptedRequestObjectTenant());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("request_object_encryption_alg_values_supported"));

        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .set("request_parameter_supported", true)
                                      .setStrings("request_object_signing_alg_values_supported", List.of("RS256"))
                                      .setStrings("request_object_encryption_alg_values_supported",
                                                  List.of("RSA-OAEP-256"))
                                      .setStrings("request_object_encryption_enc_values_supported", List.of("A256GCM"))
                                      .build()
                                      .toString());

        context = tenantContext(encryptedRequestObjectTenant());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("request_object_encryption_enc_values_supported"));
    }

    @Test
    void authorizationCodeTenantRequiresJwkSetForRequestObjectEncryption() {
        PROVIDER_METADATA.set(JsonObject.builder()
                                      .set("issuer", issuer.toString())
                                      .set("authorization_endpoint", authorizationEndpointUri.toString())
                                      .set("token_endpoint", tokenEndpointUri.toString())
                                      .setStrings("response_types_supported", List.of("code"))
                                      .setStrings("grant_types_supported", List.of("authorization_code"))
                                      .setStrings("code_challenge_methods_supported", List.of("S256"))
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("none"))
                                      .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                                      .set("request_parameter_supported", true)
                                      .setStrings("request_object_signing_alg_values_supported", List.of("RS256"))
                                      .setStrings("request_object_encryption_alg_values_supported",
                                                  List.of("RSA-OAEP-256"))
                                      .setStrings("request_object_encryption_enc_values_supported",
                                                  List.of("A128CBC-HS256"))
                                      .build()
                                      .toString());

        OidcTenantContext context = tenantContext(encryptedRequestObjectTenant());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("jwks_uri"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataResponseTypesAreMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("none"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("response_types_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDoesNotSupportCodeResponseType() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("response_types_supported", List.of("id_token"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("response_types_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDoesNotSupportAuthorizationCodeGrant() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("grant_types_supported", List.of("implicit"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("grant_types_supported"));
    }

    @Test
    void authorizationCodeTenantAcceptsMissingWellKnownMetadataGrantTypesDefault() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("none"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.ready(), is(true));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataPkceMethodsAreMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("none"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("code_challenge_methods_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDoesNotSupportConfiguredPkceMethod() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("code_challenge_methods_supported", List.of("plain"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("code_challenge_methods_supported"));
    }

    @Test
    void authorizationCodeTenantSkipsPkceMetadataWhenPkceIsDisabled() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("0123456789abcdef0123456789abcdef")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .pkceRequired(false))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
    }

    @Test
    void publicAuthorizationCodeTenantAcceptsMissingTokenEndpointAuthenticationMethods() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.ready(), is(true));
    }

    @Test
    void authorizationCodeTenantAcceptsMissingWellKnownMetadataTokenEndpointAuthForBasicDefault() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("0123456789abcdef0123456789abcdef")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
    }

    @Test
    void publicAuthorizationCodeTenantAcceptsMetadataThatOnlyAdvertisesConfidentialAuthentication() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.ready(), is(true));
    }

    @Test
    void confidentialAuthorizationCodeTenantRejectsAnUnadvertisedAuthenticationMethod() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder().from(authorizationCodeTenantConfig())
                .clientSecret("0123456789abcdef0123456789abcdef")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_POST)
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("token_endpoint_auth_methods_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataJwtAuthSigningAlgorithmsAreMissing() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_jwt"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(jwtClientAuthenticationTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("token_endpoint_auth_signing_alg_values_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataJwtAuthSigningAlgorithmDoesNotMatchConfig() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_jwt"))
                                      .setStrings("token_endpoint_auth_signing_alg_values_supported", List.of("HS512"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(jwtClientAuthenticationTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("token_endpoint_auth_signing_alg_values_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataJwtAuthSigningAlgorithmsContainNone() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_jwt"))
                                      .setStrings("token_endpoint_auth_signing_alg_values_supported",
                                                  List.of("HS256", "none"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(jwtClientAuthenticationTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("token_endpoint_auth_signing_alg_values_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataIdTokenSigningAlgorithmsAreMissing() {
        PROVIDER_METADATA.set(authorizationCodeCapabilityMetadataBuilder()
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataIdTokenSigningAlgorithmsDoNotMatchConfig() {
        PROVIDER_METADATA.set(authorizationCodeCapabilityMetadataBuilder()
                .setStrings("id_token_signing_alg_values_supported", List.of("ES256"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeSignedOnlyTenantIgnoresUnrelatedEncryptionAlgorithms() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                .setStrings("id_token_encryption_alg_values_supported", List.of("dir"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        assertThat(tenantConfig.idToken().encryptionRequired(), is(false));
        assertThat(tenantConfig.idToken().decryptionJwk().isEmpty(), is(true));
        assertReadyTenant(tenantConfig);
    }

    @Test
    void authorizationCodeSignedOnlyTenantIgnoresUnrelatedContentEncryptionAlgorithms() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                .setStrings("id_token_encryption_enc_values_supported", List.of("A192GCM"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        assertThat(tenantConfig.idToken().encryptionRequired(), is(false));
        assertThat(tenantConfig.idToken().decryptionJwk().isEmpty(), is(true));
        assertReadyTenant(tenantConfig);
    }

    @Test
    void authorizationCodeSignedOnlyTenantWorksWithoutEncryptionMetadata() {
        assertReadyTenant(authorizationCodeTenantConfig());
    }

    @Test
    void signedOnlyTenantIgnoresEmptyEncryptionCapabilityLists() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                .setStrings("id_token_encryption_alg_values_supported", List.of())
                .setStrings("id_token_encryption_enc_values_supported", List.of())
                .build().toString());

        assertReadyTenant(authorizationCodeTenantConfig());
    }

    @Test
    void localDecryptionAllowlistsAloneDoNotEnableIdTokenEncryption() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                .setStrings("id_token_encryption_alg_values_supported", List.of("RSA-OAEP"))
                .setStrings("id_token_encryption_enc_values_supported", List.of("A128CBC-HS256"))
                .build().toString());
        OidcTenantConfig tenant = OidcTenantConfig.builder().from(authorizationCodeTenantConfig())
                .idToken(idToken -> idToken
                        .allowedEncryptionAlgorithms(List.of("RSA-OAEP-256"))
                        .allowedContentEncryptionAlgorithms(List.of("A256GCM")))
                .buildPrototype();

        assertThat(tenant.idToken().encryptionRequired(), is(false));
        assertThat(tenant.idToken().decryptionJwk().isEmpty(), is(true));
        assertReadyTenant(tenant);
    }

    @Test
    void configuredIdTokenEncryptionStillRejectsIncompatibleCapabilities() {
        List<Consumer<OidcIdTokenConfig.Builder>> modes = List.of(
                idToken -> idToken.decryptionJwk(idTokenDecryptionKeys()),
                idToken -> idToken.encryptionRequired(true).decryptionJwk(idTokenDecryptionKeys()));
        for (Consumer<OidcIdTokenConfig.Builder> mode : modes) {
            for (String field : List.of("id_token_encryption_alg_values_supported", "id_token_encryption_enc_values_supported")) {
                String unsupported = field.equals("id_token_encryption_alg_values_supported") ? "dir" : "A192GCM";
                for (List<String> algorithms : List.of(List.<String>of(), List.of(unsupported))) {
                    PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                            .setStrings("id_token_encryption_alg_values_supported", List.of("RSA-OAEP"))
                            .setStrings("id_token_encryption_enc_values_supported", List.of("A256GCM"))
                            .setStrings(field, algorithms)
                            .build().toString());
                    OidcTenantConfig tenant = OidcTenantConfig.builder().from(authorizationCodeTenantConfig())
                            .idToken(mode).buildPrototype();

                    OidcTenantContext context = tenantContext(tenant);

                    assertThat(context.state(), is(OidcTenantState.FAILED));
                    assertThat(context.failureCause().orElseThrow().getMessage(), containsString(field));
                }
            }
        }
    }

    @Test
    void configuredIdTokenEncryptionAcceptsCompatibleOrAbsentCapabilities() {
        for (boolean required : List.of(false, true)) {
            for (boolean advertised : List.of(false, true)) {
                JsonObject.Builder metadata = authorizationCodeMetadataBuilder();
                if (advertised) {
                    metadata.setStrings("id_token_encryption_alg_values_supported", List.of("RSA-OAEP"))
                            .setStrings("id_token_encryption_enc_values_supported", List.of("A256GCM"));
                }
                PROVIDER_METADATA.set(metadata.build().toString());
                OidcTenantConfig tenant = OidcTenantConfig.builder().from(authorizationCodeTenantConfig())
                        .idToken(idToken -> idToken.encryptionRequired(required).decryptionJwk(idTokenDecryptionKeys()))
                        .buildPrototype();

                assertReadyTenant(tenant);
            }
        }
    }

    @Test
    void signedOnlyTenantStillRequiresCompatibleSigningMetadata() {
        for (boolean missing : List.of(false, true)) {
            JsonObject.Builder metadata = authorizationCodeMetadataBuilder()
                    .setStrings("id_token_encryption_alg_values_supported", List.of("dir"))
                    .setStrings("id_token_encryption_enc_values_supported", List.of("A192GCM"));
            if (missing) {
                metadata.unset("id_token_signing_alg_values_supported");
            } else {
                metadata.setStrings("id_token_signing_alg_values_supported", List.of("ES256"));
            }
            PROVIDER_METADATA.set(metadata.build().toString());

            OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

            assertThat(context.state(), is(OidcTenantState.FAILED));
            assertThat(context.failureCause().orElseThrow().getMessage(), containsString("id_token_signing_alg_values_supported"));
        }
    }

    @Test
    void signedOnlyTenantStillRejectsMalformedEncryptionMetadata() {
        for (String field : List.of("id_token_encryption_alg_values_supported", "id_token_encryption_enc_values_supported")) {
            PROVIDER_METADATA.set(authorizationCodeMetadataBuilder().set(field, true).build().toString());

            OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

            assertThat(context.state(), is(OidcTenantState.FAILED));
            assertThat(context.failureCause().isPresent(), is(true));
        }
    }

    @Test
    void introspectionTenantFailsWhenWellKnownMetadataIntrospectionEndpointHasFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("introspection_endpoint", issuer.resolve("/introspect#fragment").toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void tenantFailsWhenWellKnownMetadataContentTypeIsNotJson() {
        wellKnownContentType = "text/plain";
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        Throwable failureCause = context.failureCause().orElseThrow();
        assertThat(failureCause.getMessage(),
                   is("Failed to load well-known metadata from "
                              + issuer.resolve("/.well-known/openid-configuration")));
        assertThat(failureCause.getCause().getMessage(),
                   is("well-known metadata response must be application/json"));
    }

    @Test
    void tenantFailsWhenWellKnownMetadataStatusIsNotOk() {
        wellKnownStatus = Status.CREATED_201;
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        Throwable failureCause = context.failureCause().orElseThrow();
        assertThat(failureCause.getMessage(),
                   is("Failed to load well-known metadata from "
                              + issuer.resolve("/.well-known/openid-configuration")));
        assertThat(failureCause.getCause().getMessage(),
                   is("well-known metadata is unavailable: uri="
                              + issuer.resolve("/.well-known/openid-configuration")
                              + ", status=201"));
    }

    @Test
    void tenantLoadsWellKnownMetadataWhen200HasCustomReasonPhrase() {
        wellKnownStatus = Status.create(200, "Metadata Available");

        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.failureCause().map(Throwable::toString).orElse("ready"), context.ready(), is(true));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer.toString())));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
    }

    @Test
    void metadataLoaderAccepts200WithoutReasonPhrase() throws Exception {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
                ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            URI rawIssuer = new URI("http", null, listener.getInetAddress().getHostAddress(),
                                    listener.getLocalPort(), null, null, null);
            Future<?> served = executor.submit(() -> {
                try (Socket socket = listener.accept()) {
                    socket.setSoTimeout(10_000);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(),
                                                                                      StandardCharsets.ISO_8859_1));
                    for (String line = reader.readLine(); line != null && !line.isEmpty(); line = reader.readLine()) {
                        // Consume the HTTP request headers before responding.
                    }
                    byte[] json = JsonObject.builder().set("issuer", rawIssuer.toString()).build().toString()
                            .getBytes(StandardCharsets.UTF_8);
                    String response = "HTTP/1.1 200 \r\nContent-Type: application/json\r\nContent-Length: "
                            + json.length + "\r\nConnection: close\r\n\r\n";
                    socket.getOutputStream().write(response.getBytes(StandardCharsets.US_ASCII));
                    socket.getOutputStream().write(json);
                    socket.getOutputStream().flush();
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
            OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                    .issuer(rawIssuer.toString())
                    .endpoints(it -> it.tlsRequired(false))
                    .buildPrototype();
            WebClient client = WebClient.create();
            try {
                OidcProviderMetadata metadata = new OidcProviderMetadataLoader(client)
                        .load(OidcProviderMetadata.fromStaticConfig(tenantConfig), false);

                assertThat(metadata.issuer(), is(Optional.of(rawIssuer.toString())));
                served.get(10, TimeUnit.SECONDS);
            } finally {
                client.closeResource();
            }
        }
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataAuthorizationEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataAuthorizationEndpointHasFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", issuer.resolve("/authorize#fragment").toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataAuthorizationEndpointHasUnsupportedScheme() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", "ftp://issuer.example/authorize")
                .set("token_endpoint", tokenEndpointUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataTokenEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataTokenEndpointHasFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", issuer.resolve("/token#fragment").toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataTokenEndpointHasUnsupportedScheme() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", "ftp://issuer.example/token")
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void tenantFailsWhenWellKnownMetadataIssuerHasQueryOrFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer + "?tenant=default")
                .set("jwks_uri", jwksUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .endpoints(it -> it.wellKnownUri(issuer.resolve("/.well-known/openid-configuration"))
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));

        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer + "#fragment")
                .set("jwks_uri", jwksUri.toString())
                .build()
                .toString());

        context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void logoutTenantLoadsEndSessionEndpointFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.tlsRequired(false))
                .logout(logout -> logout.endSession(endSession -> endSession.idTokenHintRequired(false)))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().endSessionEndpointUri(), is(Optional.of(endSessionEndpointUri)));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void logoutTenantFailsWhenWellKnownMetadataEndSessionEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .logout(logout -> logout.endSession(endSession -> endSession.idTokenHintRequired(false)))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void logoutTenantFailsWhenWellKnownMetadataEndSessionEndpointHasFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("end_session_endpoint", issuer.resolve("/logout#fragment").toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .logout(logout -> logout.endSession(endSession -> endSession.idTokenHintRequired(false)))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void userInfoTenantLoadsUserInfoEndpointFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(_ -> { })
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().userInfoEndpointUri(), is(Optional.of(userInfoEndpointUri)));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void userInfoTenantFailsWhenWellKnownMetadataUserInfoEndpointIsMissing() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(_ -> { })
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void userInfoTenantFailsWhenWellKnownMetadataUserInfoEndpointHasFragment() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                .set("userinfo_endpoint", issuer.resolve("/userinfo#fragment").toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(_ -> { })
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void userInfoJwtTenantLoadsEncryptionMetadata() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .setStrings("userinfo_signing_alg_values_supported", List.of("RS256"))
                                      .setStrings("userinfo_encryption_alg_values_supported", List.of("RSA-OAEP-256"))
                                      .setStrings("userinfo_encryption_enc_values_supported", List.of("A256GCM"))
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = userInfoJwtTenant(jwt -> jwt
                .signingAlgorithm("RS256")
                .encryptionAlgorithm("RSA-OAEP-256")
                .contentEncryptionAlgorithm("A256GCM")
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype()));

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().userInfoSigningAlgorithmsSupported(), is(Optional.of(List.of("RS256"))));
        assertThat(context.metadata().userInfoEncryptionAlgorithmsSupported(),
                   is(Optional.of(List.of("RSA-OAEP-256"))));
        assertThat(context.metadata().userInfoContentEncryptionAlgorithmsSupported(),
                   is(Optional.of(List.of("A256GCM"))));
    }

    @Test
    void userInfoJwtTenantRejectsUnsupportedMetadataAlgorithms() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .setStrings("userinfo_signing_alg_values_supported", List.of("ES256"))
                                      .build()
                                      .toString());
        OidcTenantContext signingContext = tenantContext(userInfoJwtTenant(jwt -> jwt.signingAlgorithm("RS256")));

        assertThat(signingContext.state(), is(OidcTenantState.FAILED));
        assertThat(signingContext.failureCause().orElseThrow().getMessage(),
                   containsString("userinfo_signing_alg_values_supported"));

        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .setStrings("userinfo_encryption_alg_values_supported", List.of("RSA-OAEP"))
                                      .build()
                                      .toString());
        OidcTenantContext encryptionContext = tenantContext(userInfoJwtTenant(jwt -> jwt
                .encryptionAlgorithm("RSA-OAEP-256")
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype())));

        assertThat(encryptionContext.state(), is(OidcTenantState.FAILED));
        assertThat(encryptionContext.failureCause().orElseThrow().getMessage(),
                   containsString("userinfo_encryption_alg_values_supported"));
    }

    @Test
    void userInfoJwtTenantValidatesDefaultContentEncryptionMetadata() {
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .setStrings("userinfo_encryption_alg_values_supported", List.of("RSA-OAEP-256"))
                                      .setStrings("userinfo_encryption_enc_values_supported", List.of("A256GCM"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(userInfoJwtTenant(jwt -> jwt
                .encryptionAlgorithm("RSA-OAEP-256")
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype())));

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("userinfo_encryption_enc_values_supported"));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("A128CBC-HS256"));
    }

    @Test
    void jwtProtectedResourceTenantLoadsJwkSetUriFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer.toString())));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.of(jwksUri)));
    }

    @Test
    void introspectionWithStaticEndpointDiscoversIssuerForIdentityMapping() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(endpoints -> endpoints
                        .introspectionEndpointUri(introspectionEndpointUri)
                        .wellKnownUri(issuer.resolve("/.well-known/openid-configuration"))
                        .tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer.toString())));
        assertThat(OidcSubjectMapper.principalId(JsonObject.builder().set("sub", "123").build(), context).orElseThrow(),
                   is(OidcTestIdentities.issuerSubject(issuer.toString(), "123")));
    }

    @Test
    void discoveredIssuerTakesPrecedenceOverLocalIdentityNamespace() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret")
                .subjectMapping(mapping -> mapping.principalIdNamespace("fallback"))
                .endpoints(endpoints -> endpoints
                        .introspectionEndpointUri(introspectionEndpointUri)
                        .wellKnownUri(issuer.resolve("/.well-known/openid-configuration"))
                        .tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(1));
        assertThat(OidcSubjectMapper.principalId(JsonObject.builder().set("sub", "123").build(), context).orElseThrow(),
                   is(OidcTestIdentities.issuerSubject(issuer.toString(), "123")));
    }

    @Test
    void introspectionProtectedResourceTenantLoadsEndpointFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .webClient(tenantWebClient())
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().introspectionEndpointUri(), is(Optional.of(introspectionEndpointUri)));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void introspectionTenantFailsWhenWellKnownMetadataDoesNotSupportConfiguredAuthenticationMethod() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("introspection_endpoint", introspectionEndpointUri.toString())
                .setStrings("introspection_endpoint_auth_methods_supported", List.of("private_key_jwt"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void introspectionTenantFailsWhenWellKnownMetadataDoesNotSupportConfiguredSigningAlgorithm() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("introspection_endpoint", introspectionEndpointUri.toString())
                .setStrings("introspection_endpoint_auth_methods_supported", List.of("client_secret_jwt"))
                .setStrings("introspection_endpoint_auth_signing_alg_values_supported", List.of("HS512"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("0123456789abcdef0123456789abcdef")
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")
                        .introspection(introspection -> introspection
                                .authenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT))))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void jwtIntrospectionRejectsMissingDiscoveredSigningAlgorithms() {
        for (OidcClientAuthenticationMethod method : JWT_AUTHENTICATION_METHODS) {
            PROVIDER_METADATA.set(jwtIntrospectionMetadata(method)
                    .unset("introspection_endpoint_auth_signing_alg_values_supported").build().toString());
            int requests = WELL_KNOWN_REQUESTS.get();

            OidcTenantContext context = tenantContext(jwtIntrospectionTenant(method, _ -> { }).buildPrototype());

            assertThat(method.name(), context.state(), is(OidcTenantState.FAILED));
            assertThat(context.failureCause().orElseThrow().getMessage(),
                       is("well-known metadata introspection_endpoint_auth_signing_alg_values_supported must be present for "
                                  + method.wireName()));
            assertThat(WELL_KNOWN_REQUESTS.get(), is(requests + 1));
        }
    }

    @Test
    void jwtIntrospectionRejectsUnsupportedDiscoveredSigningAlgorithms() {
        for (OidcClientAuthenticationMethod method : JWT_AUTHENTICATION_METHODS) {
            boolean privateKey = method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT;
            PROVIDER_METADATA.set(jwtIntrospectionMetadata(method)
                    .setStrings("introspection_endpoint_auth_signing_alg_values_supported",
                                List.of(privateKey ? "RS512" : "HS512")).build().toString());

            OidcTenantContext context = tenantContext(jwtIntrospectionTenant(method, _ -> { }).buildPrototype());

            assertThat(method.name(), context.state(), is(OidcTenantState.FAILED));
            assertThat(context.failureCause().orElseThrow().getMessage(),
                       is("well-known metadata introspection_endpoint_auth_signing_alg_values_supported must include "
                                  + (privateKey ? "RS256" : "HS256")));
        }
    }

    @Test
    void jwtIntrospectionRejectsUnadvertisedAuthenticationMethods() {
        for (OidcClientAuthenticationMethod method : JWT_AUTHENTICATION_METHODS) {
            PROVIDER_METADATA.set(jwtIntrospectionMetadata(method)
                    .setStrings("introspection_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                    .build().toString());

            OidcTenantContext context = tenantContext(jwtIntrospectionTenant(method, _ -> { }).buildPrototype());

            assertThat(method.name(), context.state(), is(OidcTenantState.FAILED));
            assertThat(context.failureCause().orElseThrow().getMessage(),
                       is("well-known metadata introspection_endpoint_auth_methods_supported must include " + method.wireName()));
        }
    }

    @Test
    void jwtIntrospectionWithStaticEndpointStillChecksLoadedDiscovery() {
        for (OidcClientAuthenticationMethod method : JWT_AUTHENTICATION_METHODS) {
            PROVIDER_METADATA.set(jwtIntrospectionMetadata(method)
                    .unset("introspection_endpoint_auth_signing_alg_values_supported").build().toString());
            OidcTenantConfig tenant = jwtIntrospectionTenant(method, _ -> { })
                    .clearIssuer()
                    .endpoints(endpoints -> endpoints
                            .introspectionEndpointUri(introspectionEndpointUri)
                            .wellKnownUri(issuer.resolve("/.well-known/openid-configuration"))
                            .tlsRequired(false))
                    .buildPrototype();
            int requests = WELL_KNOWN_REQUESTS.get();

            OidcTenantContext context = tenantContext(tenant);

            assertThat(method.name(), context.state(), is(OidcTenantState.FAILED));
            assertThat(context.failureCause().orElseThrow().getMessage(),
                       is("well-known metadata introspection_endpoint_auth_signing_alg_values_supported must be present for "
                                  + method.wireName()));
            assertThat(WELL_KNOWN_REQUESTS.get(), is(requests + 1));
        }
    }

    @Test
    void staticJwtIntrospectionCanUseIdentityNamespaceWithoutDiscovery() {
        for (OidcClientAuthenticationMethod method : JWT_AUTHENTICATION_METHODS) {
            OidcTenantConfig tenant = jwtIntrospectionTenant(method, _ -> { })
                    .clearIssuer()
                    .subjectMapping(mapping -> mapping.principalIdNamespace("resource-authority"))
                    .endpoints(endpoints -> endpoints.introspectionEndpointUri(introspectionEndpointUri).tlsRequired(false))
                    .buildPrototype();

            OidcTenantContext context = tenantContext(tenant);

            try {
                assertThat(method.name(), context.state(), is(OidcTenantState.READY));
                assertThat(context.metadata().wellKnownUri(), is(Optional.empty()));
                assertThat(context.metadata().introspectionEndpointAuthenticationSigningAlgorithmsSupported(), is(Optional.empty()));
                assertThat(context.introspectionClientAuthentication().clientAssertionAlgorithm(),
                           is(Optional.of(method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT ? "RS256" : "HS256")));
                assertThat(WELL_KNOWN_REQUESTS.get(), is(0));
            } finally {
                if (context.ready()) {
                    context.webClient().closeResource();
                }
            }
        }
    }

    @Test
    void staticJwtIntrospectionStillValidatesLocalCredentialsAndAlgorithms() {
        for (OidcClientAuthenticationMethod method : JWT_AUTHENTICATION_METHODS) {
            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> jwtIntrospectionTenant(method, assertion -> assertion.algorithm("none"))
                            .endpoints(endpoints -> endpoints.introspectionEndpointUri(introspectionEndpointUri).tlsRequired(false))
                            .buildPrototype());
            assertThat(failure.getMessage(), containsString("client-assertion.algorithm must not be blank, padded, or none"));
        }
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> jwtIntrospectionTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT, _ -> { })
                        .clientSecret("too-short")
                        .endpoints(endpoints -> endpoints.introspectionEndpointUri(introspectionEndpointUri).tlsRequired(false))
                        .buildPrototype());
        assertThat(failure.getMessage(), containsString("CLIENT_SECRET_JWT Introspection Endpoint authentication"));
    }

    @Test
    void staticPrivateKeyJwtIntrospectionStillValidatesSigningKey() {
        OidcTenantConfig tenant = jwtIntrospectionTenant(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                                        assertion -> assertion.keyId("missing"))
                .endpoints(endpoints -> endpoints.introspectionEndpointUri(introspectionEndpointUri).tlsRequired(false))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenant);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   is("client-assertion.key-id does not match a configured JWK"));
        assertThat(WELL_KNOWN_REQUESTS.get(), is(0));
    }

    @Test
    void staticJwtIntrospectionStillRequiresHttps() {
        for (OidcClientAuthenticationMethod method : JWT_AUTHENTICATION_METHODS) {
            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> jwtIntrospectionTenant(method, _ -> { })
                            .issuer("https://issuer.example")
                            .endpoints(endpoints -> endpoints.introspectionEndpointUri(introspectionEndpointUri))
                            .buildPrototype());
            assertThat(failure.getMessage(), containsString("introspection-endpoint-uri must use https"));
        }
    }

    @Test
    void introspectionProtectedResourceTenantFailsWhenWellKnownMetadataEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void targetClientCredentialsGrantTenantLoadsTokenEndpointFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype();

        OidcTenantContext context = OidcTenantRuntimeRegistry.create(providerConfig)
                .tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().tokenEndpointUri(), is(Optional.of(tokenEndpointUri)));
    }

    @Test
    void targetClientCredentialsGrantTenantFailsWhenWellKnownMetadataGrantTypesAreMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype();

        OidcTenantContext context = OidcTenantRuntimeRegistry.create(providerConfig)
                .tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("grant_types_supported"));
    }

    @Test
    void targetClientCredentialsGrantTenantFailsWhenWellKnownMetadataTokenEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype();

        OidcTenantContext context = OidcTenantRuntimeRegistry.create(providerConfig)
                .tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void mutualTlsTenantFailsWhenWellKnownMetadataTokenEndpointAliasHasFragment() {
        URI httpsIssuer = URI.create("https://issuer.example");
        OidcProviderMetadata wellKnownMetadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", httpsIssuer.toString())
                .set("token_endpoint", httpsIssuer.resolve("/token").toString())
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("token_endpoint", "https://issuer.example/mtls-token#fragment")
                        .build())
                .build());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(httpsIssuer.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.tokenEndpointUri(httpsIssuer.resolve("/configured-token")))
                .buildPrototype();
        OidcProviderMetadata metadata = OidcProviderMetadata.fromStaticConfig(tenantConfig)
                .mergeWellKnownMetadata(wellKnownMetadata);

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantContextFactory.validateMutualTlsMetadata(
                                                               tenantConfig,
                                                               metadata));

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must not include a fragment"));
    }

    @Test
    void mutualTlsTenantFailsWhenWellKnownMetadataTokenEndpointAliasIsInsecure() {
        URI httpsIssuer = URI.create("https://issuer.example");
        OidcProviderMetadata wellKnownMetadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", httpsIssuer.toString())
                .set("token_endpoint", httpsIssuer.resolve("/token").toString())
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("token_endpoint", "http://issuer.example/mtls-token")
                        .build())
                .build());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(httpsIssuer.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.tokenEndpointUri(httpsIssuer.resolve("/configured-token")))
                .buildPrototype();
        OidcProviderMetadata metadata = OidcProviderMetadata.fromStaticConfig(tenantConfig)
                .mergeWellKnownMetadata(wellKnownMetadata);

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantContextFactory.validateMutualTlsMetadata(
                                                               tenantConfig,
                                                               metadata));

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must use https"));
    }

    @Test
    void mutualTlsIntrospectionTenantFailsWhenWellKnownAliasIsInsecure() {
        URI httpsIssuer = URI.create("https://issuer.example");
        OidcProviderMetadata wellKnownMetadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", httpsIssuer.toString())
                .set("introspection_endpoint", httpsIssuer.resolve("/introspect").toString())
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("introspection_endpoint", "http://issuer.example/mtls-introspect")
                        .build())
                .build());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(httpsIssuer.toString())
                .clientId("client-id")
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.introspectionEndpointUri(httpsIssuer.resolve("/configured-introspect")))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")
                        .introspection(introspection -> introspection
                                .authenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH))))
                .buildPrototype();
        OidcProviderMetadata metadata = OidcProviderMetadata.fromStaticConfig(tenantConfig)
                .mergeWellKnownMetadata(wellKnownMetadata);

        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> OidcTenantContextFactory.validateMutualTlsIntrospectionMetadata(tenantConfig, metadata));

        assertThat(thrown.getMessage(),
                   containsString("introspection-endpoint-uri must use https"));
    }

    @Test
    void wellKnownMetadataRedirectIsNotFollowedWhenTenantWebClientFollowsRedirects() {
        redirectLocation = issuer.resolve("/redirected-openid-configuration").toString();
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .webClient(redirectFollowingTenantWebClient())
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(REDIRECTED_WELL_KNOWN_REQUESTS.get(), is(0));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void jwtProtectedResourceTenantFailsWhenWellKnownMetadataJwkSetUriIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    private static OidcTenantConfig.Builder staticHttpsAuthorizationCodeTenant(
            URI wellKnownUri,
            Consumer<OidcEndpointConfig.Builder> endpointCustomizer) {
        return OidcTenantConfig.builder()
                .issuer(HTTPS_ISSUER.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(endpoints -> {
                    endpoints.wellKnownUri(wellKnownUri)
                            .authorizationEndpointUri(HTTPS_ISSUER.resolve("authorize"))
                            .tokenEndpointUri(HTTPS_ISSUER.resolve("token"));
                    endpointCustomizer.accept(endpoints);
                })
                .authorizationCode(code -> code.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(cookies -> cookies.protection(protection -> protection.password("test-cookie-password")));
    }

    private static OidcTenantConfig metadataOnlyAuthorizationCodeTenant(URI wellKnownUri) {
        return OidcTenantConfig.builder()
                .clientId("client-id")
                .endpoints(endpoints -> endpoints.wellKnownUri(wellKnownUri).tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(cookies -> cookies.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
    }

    private static OutboundTarget clientCredentialsTarget() {
        return OutboundTarget.builder("api")
                .customObject(OidcOutboundPolicyConfig.class,
                              OidcOutboundPolicyConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .buildPrototype())
                .build();
    }

    private static WebClientConfig tenantWebClient() {
        return WebClientConfig.builder()
                .addHeader(TENANT_WEBCLIENT_HEADER, TENANT_WEBCLIENT_HEADER_VALUE)
                .buildPrototype();
    }

    private static WebClientConfig mutualTlsWebClient() {
        Keys privateKeyConfig = clientKeys();
        return WebClientConfig.builder()
                .tls(tls -> tls
                        .privateKey(privateKeyConfig)
                        .privateKeyCertChain(privateKeyConfig))
                .buildPrototype();
    }

    private static Keys clientKeys() {
        return Keys.builder()
                .keystore(store -> store
                        .passphrase("password")
                        .keystore(Resource.create("client.p12")))
                .build();
    }

    private static WebClientConfig redirectFollowingTenantWebClient() {
        return WebClientConfig.builder()
                .addHeader(TENANT_WEBCLIENT_HEADER, TENANT_WEBCLIENT_HEADER_VALUE)
                .followRedirects(true)
                .buildPrototype();
    }

    private static OidcProviderConfig multiIssuerProviderConfig(OidcTenantConfig tenantConfig,
                                                                URI otherRedirectionEndpointUri) {
        OidcTenantConfig otherTenant = OidcTenantConfig.builder()
                .issuer("https://other-issuer.example")
                .clientId("other-client")
                .endpoints(endpoints -> endpoints
                        .authorizationEndpointUri(URI.create("https://other-issuer.example/authorize"))
                        .tokenEndpointUri(URI.create("https://other-issuer.example/token"))
                        .jwksUri(URI.create("https://other-issuer.example/jwks")))
                .authorizationCode(authorizationCode -> authorizationCode
                        .redirectionEndpointUri(otherRedirectionEndpointUri))
                .cookies(cookies -> cookies.protection(protection -> protection.password("other-cookie-password")))
                .buildPrototype();
        return OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .putTenant("other", otherTenant)
                .buildPrototype();
    }

    private static OidcTenantContext tenantContext(OidcTenantConfig tenantConfig) {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .buildPrototype());
        return registry.tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();
    }

    private static ResourceConfig idTokenDecryptionKeys() {
        return ResourceConfig.builder().resourcePath("oidc-next-encrypt-jwk.json").buildPrototype();
    }

    private static void assertReadyTenant(OidcTenantConfig tenant) {
        int requests = WELL_KNOWN_REQUESTS.get();
        OidcTenantContext context = tenantContext(tenant);
        try {
            assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                       context.state(), is(OidcTenantState.READY));
            assertThat(WELL_KNOWN_REQUESTS.get(), is(requests + 1));
        } finally {
            if (context.ready()) {
                context.webClient().closeResource();
            }
        }
    }

    private OidcTenantConfig userInfoJwtTenant(Consumer<OidcUserInfoJwtConfig.Builder> customizer) {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(userInfo -> userInfo.jwt(customizer))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
    }

    private JsonObject.Builder httpsAuthorizationCodeMetadataBuilder() {
        return authorizationCodeMetadataBuilder()
                .set("issuer", HTTPS_ISSUER.toString())
                .set("authorization_endpoint", HTTPS_ISSUER.resolve("authorize").toString())
                .set("token_endpoint", HTTPS_ISSUER.resolve("token").toString())
                .set("jwks_uri", HTTPS_ISSUER.resolve("jwks").toString());
    }

    private JsonObject.Builder providerMetadataBuilder() {
        return authorizationCodeMetadataBuilder()
                .set("introspection_endpoint", introspectionEndpointUri.toString())
                .set("userinfo_endpoint", userInfoEndpointUri.toString())
                .set("end_session_endpoint", endSessionEndpointUri.toString());
    }

    private JsonObject.Builder authorizationCodeMetadataBuilder() {
        return authorizationCodeCapabilityMetadataBuilder()
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"));
    }

    private JsonObject.Builder authorizationCodeCapabilityMetadataBuilder() {
        return JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code", "client_credentials"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("none", "client_secret_basic"));
    }

    private OidcTenantConfig authorizationCodeTenantConfig() {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
    }

    private OidcTenantConfig encryptedRequestObjectTenant() {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .requestObject(requestObject -> requestObject.mode(OidcRequestObjectMode.REQUIRED)
                                .signingJwk(jwk -> jwk.resourcePath("oidc-next-sign-jwk.json"))
                                .signingKeyId("sign-rsa")
                                .signingAlgorithm("RS256")
                                .encryptionAlgorithm("RSA-OAEP-256")))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
    }

    private OidcTenantConfig jwtClientAuthenticationTenantConfig() {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("0123456789abcdef0123456789abcdef")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
    }

    private OidcTenantConfig.Builder jwtIntrospectionTenant(OidcClientAuthenticationMethod method,
                                                           Consumer<OidcClientAssertionConfig.Builder> assertionCustomizer) {
        boolean privateKey = method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT;
        OidcClientAssertionConfig.Builder assertion = OidcClientAssertionConfig.builder()
                .algorithm(privateKey ? "RS256" : "HS256");
        if (privateKey) {
            assertion.jwk(ResourceConfig.builder()
                    .resourcePath("oidc-next-sign-jwk.json")
                    .buildPrototype()).keyId("sign-rsa");
        }
        assertionCustomizer.accept(assertion);
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("introspection-client")
                .clientSecret("0123456789abcdef0123456789abcdef")
                .endpoints(endpoints -> endpoints.tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")
                        .introspection(introspection -> introspection.authenticationMethod(method)
                                .clientAssertion(assertion.buildPrototype()))));
    }

    private JsonObject.Builder jwtIntrospectionMetadata(OidcClientAuthenticationMethod method) {
        return JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("introspection_endpoint", introspectionEndpointUri.toString())
                .setStrings("introspection_endpoint_auth_methods_supported", List.of(method.wireName()))
                .setStrings("introspection_endpoint_auth_signing_alg_values_supported",
                            List.of(method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT ? "RS256" : "HS256"));
    }

    private static final class MutableClock extends Clock {
        private final ZoneId zone;
        private volatile Instant instant;

        private MutableClock(Instant instant, ZoneId zone) {
            this.instant = instant;
            this.zone = zone;
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

        private static MutableClock create(Instant instant) {
            return new MutableClock(instant, ZoneId.of("UTC"));
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }
    }
}
