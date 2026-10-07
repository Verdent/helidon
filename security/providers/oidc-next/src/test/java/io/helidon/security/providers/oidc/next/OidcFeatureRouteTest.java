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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

import io.helidon.common.configurable.AllowList;
import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.RequestedUriDiscoveryContext;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonArray;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.json.JsonString;
import io.helidon.json.JsonValue;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.EndpointConfig;
import io.helidon.security.Grant;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.Role;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.security.providers.oidc.next.spi.OidcTenantAdapter;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ServerTest
class OidcFeatureRouteTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI ATTACKER_ISSUER = URI.create("https://attacker.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI JWKS_URI = URI.create("https://issuer.example/jwks");
    private static final URI END_SESSION_ENDPOINT_URI = URI.create("https://issuer.example/logout");
    private static final URI CONFIGURED_REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI POST_LOGOUT_REDIRECT_URI = URI.create("https://rp.example/logged-out");
    private static final URI OTHER_POST_LOGOUT_REDIRECT_URI = URI.create("https://rp.example/other-logged-out");
    private static final String COOKIE_PASSWORD = "test-cookie-password";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_SECRET = "client-secret";
    private static final String SUBJECT = "user1-id";
    private static final String USERNAME = "user1";
    private static final String EMAIL = "user1@example.org";
    private static final String STATE = OidcAuthorizationState.create(
            "default",
            Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32])).value();
    private static final String NONCE = "nonce";
    private static final String PKCE_VERIFIER = "pkce-verifier";
    private static final AtomicInteger TOKEN_REQUESTS = new AtomicInteger();
    private static final AtomicReference<String> USER_INFO_AUTHORIZATION = new AtomicReference<>();
    private static final AtomicReference<String> TOKEN_CLIENT_ASSERTION = new AtomicReference<>();
    private static final AtomicReference<String> COLLIDING_ISSUER_METADATA = new AtomicReference<>();
    private static final AtomicInteger ATTACKER_TOKEN_REQUESTS = new AtomicInteger();

    private static JwkKeys signKeys;
    private static JwkKeys encryptKeys;
    private static String verifyJwkSet;
    private static String singleVerifyJwkSet;
    private static String tokenEndpointResponseBody;
    private static String userInfoEndpointResponseBody;
    private static Status userInfoEndpointStatus;
    private static String userInfoEndpointContentType;

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        encryptKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-encrypt-jwk.json"))
                .build();
        verifyJwkSet = Resource.create("oidc-next-verify-public-jwk.json").string();
        singleVerifyJwkSet = Resource.create("oidc-next-verify-public-jwk.json").string();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        OidcFeature.create(providerConfig()).setup(routing);
        routing.post("/token", (request, response) -> {
            TOKEN_REQUESTS.incrementAndGet();
            TOKEN_CLIENT_ASSERTION.set(request.content().as(Parameters.class).first("client_assertion").orElse(""));
            tokenEndpointResponse(response);
        });
        routing.post("/attacker-token", (_, response) -> {
            ATTACKER_TOKEN_REQUESTS.incrementAndGet();
            tokenEndpointResponse(response);
        });
        routing.get("/issuer-collision-metadata", (_, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(COLLIDING_ISSUER_METADATA.get()));
        routing.get("/userinfo", (request, response) -> {
            USER_INFO_AUTHORIZATION.set(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""));
            response.status(userInfoEndpointStatus);
            if (userInfoEndpointStatus.family() == Status.Family.SUCCESSFUL && userInfoEndpointContentType != null) {
                response.header(HeaderNames.CONTENT_TYPE, userInfoEndpointContentType);
            }
            response.send(userInfoEndpointResponseBody);
        });
        routing.get("/jwks", (_, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(verifyJwkSet));
        routing.get("/single-jwks", (_, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(singleVerifyJwkSet));
    }

    @BeforeEach
    void setUp() {
        tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken(NONCE)).toString();
        userInfoEndpointResponseBody = userInfoEndpointResponse(SUBJECT).build().toString();
        userInfoEndpointStatus = Status.OK_200;
        userInfoEndpointContentType = "application/json";
        USER_INFO_AUTHORIZATION.set("");
        TOKEN_CLIENT_ASSERTION.set("");
        COLLIDING_ISSUER_METADATA.set("");
        ATTACKER_TOKEN_REQUESTS.set(0);
        TOKEN_REQUESTS.set(0);
    }

    @Test
    void redirectionEndpointRouteRejectsMissingState(WebClient client) {
        try (HttpClientResponse response = client.get("/oidc/callback")
                .queryParam("code", "authorization-code")
                .request()) {
            assertThat(response.status(), is(Status.BAD_REQUEST_400));
            assertThat(response.as(String.class), is("Authorization Response is invalid"));
        }
    }

    @Test
    void sharedMultiIssuerCallbackRejectsMissingIssuerBeforeWrongTokenEndpoint(URI serverUri) {
        String attackerTenantId = "attacker";
        String attackerState = authorizationState(attackerTenantId, 1);
        OidcTenantConfig honestTenant = tenantConfig(serverUri);
        OidcTenantConfig attackerTenant = OidcTenantConfig.builder()
                .issuer(ATTACKER_ISSUER.toString())
                .clientId(CLIENT_ID)
                .endpoints(endpoints -> endpoints
                        // The malicious tenant declares the honest Authorization Endpoint and its own Token Endpoint.
                        .authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(serverUri.resolve("attacker-token"))
                        .jwksUri(serverUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(authorizationCode -> authorizationCode
                        .redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .cookies(cookies -> cookies.protection(protection -> protection.password(COOKIE_PASSWORD)))
                .buildPrototype();
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("honest", honestTenant)
                .putTenant(attackerTenantId, attackerTenant)
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(config);
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(attackerTenantId,
                                                                attackerState,
                                                                ATTACKER_ISSUER.toString(),
                                                                callbackUri,
                                                                attackerTenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "honest-authorization-code")
                    .queryParam("state", attackerState)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(response.as(String.class), is("Authorization Response is invalid"));
                assertThat(ATTACKER_TOKEN_REQUESTS.get(), is(0));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void sharedIssuerExceptionRejectsWrongCallbackBeforeTokenEndpoint(URI serverUri) {
        OidcTenantConfig honest = tenantConfig(serverUri,
                                               code -> code.redirectionEndpointUri(URI.create("/oidc/honest-callback")));
        OidcTenantConfig other = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(endpoints -> endpoints
                        .authorizationEndpointUri(URI.create("https://other.example/authorize"))
                        .tokenEndpointUri(serverUri.resolve("attacker-token"))
                        .jwksUri(serverUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(URI.create("/oidc/other-callback")))
                .cookies(cookies -> cookies.protection(protection -> protection.password(COOKIE_PASSWORD)))
                .buildPrototype();
        OidcProviderConfig config = OidcProviderConfig.builder()
                .issuerUniquenessValidationEnabled(false)
                .putTenant("honest", honest)
                .putTenant("other", other)
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(config);
        try {
            String state = authorizationState("other", 4);
            SetCookie stateCookie = authenticationRequestCookie("other",
                                                                state,
                                                                ISSUER.toString(),
                                                                rpBaseUri(rpServer).resolve("/oidc/other-callback"),
                                                                other);
            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/honest-callback")
                    .followRedirects(false)
                    .queryParam("code", "honest-authorization-code")
                    .queryParam("state", state)
                    .queryParam("iss", ISSUER.toString())
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(ATTACKER_TOKEN_REQUESTS.get(), is(0));
                assertThat(TOKEN_REQUESTS.get(), is(0));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void sharedCallbackRejectsCollidingDiscoveredIssuerBeforeWrongTokenEndpoint(URI serverUri) {
        String attackerTenantId = "attacker";
        String attackerState = authorizationState(attackerTenantId, 2);
        OidcProviderConfig config = collidingIssuerProviderConfig(serverUri);
        OidcTenantConfig attackerTenant = config.tenants().get(attackerTenantId);
        WebServer rpServer = oidcFeatureServer(config);
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(attackerTenantId,
                                                                attackerState,
                                                                ISSUER.toString(),
                                                                callbackUri,
                                                                attackerTenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "honest-authorization-code")
                    .queryParam("state", attackerState)
                    .queryParam("iss", ISSUER.toString())
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(ATTACKER_TOKEN_REQUESTS.get(), is(0));
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(response.as(String.class), is("Authorization Response is invalid"));
                assertThat(TOKEN_REQUESTS.get(), is(0));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void collidingIssuerFailsRegardlessOfTenantInitializationOrder(URI serverUri) {
        OidcProviderConfig config = collidingIssuerProviderConfig(serverUri);

        for (boolean honestFirst : List.of(true, false)) {
            try (OidcProvider provider = OidcProvider.create(config)) {
                String first = honestFirst ? "honest" : "attacker";
                String second = honestFirst ? "attacker" : "honest";
                OidcTenantRuntimeRegistry registry = provider.tenantRuntimeRegistry();
                OidcTenantContext firstContext = registry.tenantContext(first).orElseThrow();
                OidcTenantContext secondContext = registry.tenantContext(second).orElseThrow();
                OidcTenantContext honestContext = honestFirst ? firstContext : secondContext;
                OidcTenantContext attackerContext = honestFirst ? secondContext : firstContext;

                assertThat(honestContext.state(), is(OidcTenantState.READY));
                assertThat(attackerContext.state(), is(OidcTenantState.FAILED));
                assertThat(attackerContext.retryableFailure(), is(false));
                assertThat(ATTACKER_TOKEN_REQUESTS.get(), is(0));
            }
        }
    }

    @Test
    void collidingIssuerFailsWithConcurrentVirtualThreadInitialization(URI serverUri) throws Exception {
        OidcProviderConfig config = collidingIssuerProviderConfig(serverUri);
        CountDownLatch start = new CountDownLatch(1);

        try (OidcProvider provider = OidcProvider.create(config);
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            OidcTenantRuntimeRegistry registry = provider.tenantRuntimeRegistry();
            Future<OidcTenantContext> honest = executor.submit(() -> {
                start.await();
                return registry.tenantContext("honest").orElseThrow();
            });
            Future<OidcTenantContext> attacker = executor.submit(() -> {
                start.await();
                return registry.tenantContext("attacker").orElseThrow();
            });
            start.countDown();

            assertThat(honest.get(5, TimeUnit.SECONDS).state(), is(OidcTenantState.READY));
            assertThat(attacker.get(5, TimeUnit.SECONDS).state(), is(OidcTenantState.FAILED));
            assertThat(ATTACKER_TOKEN_REQUESTS.get(), is(0));
        } finally {
            start.countDown();
        }
    }

    @Test
    void featureRegistersRoutesOnConfiguredSocket() {
        OidcTenantConfig tenant = tenantConfigWithLogout();
        OidcProviderConfig config = OidcProviderConfig.builder()
                .socket("oidc")
                .putTenant("default", tenant)
                .buildPrototype();
        WebServer server = WebServer.builder()
                .port(0)
                .putSocket("oidc", socket -> socket.name("oidc").port(0))
                .addFeature(OidcFeature.create(config))
                .build()
                .start();
        WebClient client = WebClient.create();
        try {
            try (HttpClientResponse response = client.get("http://localhost:" + server.port("oidc") + "/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(response.as(String.class), is("Authorization Response is invalid"));
            }
            try (HttpClientResponse response = client.get("http://localhost:" + server.port() + "/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .request()) {
                assertThat(response.status(), is(Status.NOT_FOUND_404));
            }
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");
            try (HttpClientResponse response = client.post("http://localhost:" + server.port("oidc") + "/oidc/logout")
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.FORBIDDEN_403));
            }
            try (HttpClientResponse response = client.post("http://localhost:" + server.port() + "/oidc/logout")
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.NOT_FOUND_404));
            }
        } finally {
            client.closeResource();
            server.stop();
        }
    }

    @Test
    void featureRejectsMissingRequiredSocket() {
        OidcProviderConfig config = OidcProviderConfig.builder()
                .socket("oidc")
                .putTenant("default", tenantConfig())
                .buildPrototype();

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> WebServer.builder()
                                                               .port(0)
                                                               .addFeature(OidcFeature.create(config))
                                                               .build());

        assertThat(thrown.getMessage(), containsString("socket \"oidc\""));
        assertThat(thrown.getMessage(), containsString("must be present"));
    }

    @Test
    void featureFallsBackToDefaultSocketWhenConfiguredSocketIsNotRequired() {
        OidcProviderConfig config = OidcProviderConfig.builder()
                .socket("oidc")
                .socketRequired(false)
                .putTenant("default", tenantConfig())
                .buildPrototype();
        WebServer server = WebServer.builder()
                .port(0)
                .addFeature(OidcFeature.create(config))
                .build()
                .start();
        WebClient client = WebClient.create();
        try {
            try (HttpClientResponse response = client.get("http://localhost:" + server.port() + "/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(response.as(String.class), is("Authorization Response is invalid"));
            }
        } finally {
            client.closeResource();
            server.stop();
        }
    }

    @Test
    void redirectionEndpointRouteHandlesAuthorizationErrorBeforeTokenExchange(WebClient client, URI serverUri) {
        Instant now = Instant.now();
        URI callbackUri = serverUri.resolve("oidc/callback");
        SetCookie stateCookie = OidcCookieStateHandler.create("default", tenantConfig())
                .createAuthenticationRequestCookies(new OidcAuthenticationRequestState("default",
                                                                                         STATE,
                                                                                         "nonce",
                                                                                         "pkce-verifier",
                                                                                         null,
                                                                                         ISSUER.toString(),
                                                                                         serverUri.resolve("resource"),
                                                                                         callbackUri,
                                                                                         List.of("openid", "profile"),
                                                                                         now.minusSeconds(1),
                                                                                         now.plusSeconds(60)), false, Map.of())
                .getFirst();

        try (HttpClientResponse response = client.get("/oidc/callback")
                .queryParam("error", "access_denied")
                .queryParam("state", STATE)
                .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                .request()) {
            assertThat(response.status(), is(Status.BAD_REQUEST_400));
            assertThat(response.as(String.class), is("OpenID Provider returned an Authorization Error Response"));

            List<String> removalCookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
            assertThat(removalCookies.size(), is(1));
            assertThat(removalCookies.getFirst(), containsString("__Host-helidon-oidc-state="));
            assertThat(removalCookies.getFirst(), containsString("Expires="));
        }
    }

    @Test
    void tenantInitializationAdmissionPreservesCallbackTransactionsAndLocalLogout(URI serverUri) throws Exception {
        for (boolean logout : List.of(false, true)) {
            TOKEN_REQUESTS.set(0);
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            AtomicInteger discoveryRequests = new AtomicInteger();
            AtomicReference<String> metadata = new AtomicReference<>();
            WebServer discovery = WebServer.builder()
                    .port(0)
                    .routing(routing -> routing.get("/.well-known/openid-configuration", (_, response) -> {
                        discoveryRequests.incrementAndGet();
                        entered.countDown();
                        try {
                            if (!release.await(10, TimeUnit.SECONDS)) {
                                throw new IllegalStateException("Test did not release discovery");
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException(e);
                        }
                        response.header(HeaderValues.CONTENT_TYPE_JSON).send(metadata.get());
                    }))
                    .build().start();
            try {
                URI discoveryIssuer = URI.create("http://localhost:" + discovery.port());
                metadata.set(JsonObject.builder().set("issuer", discoveryIssuer.toString())
                                     .set("authorization_endpoint", AUTHORIZATION_ENDPOINT_URI.toString())
                                     .set("token_endpoint", serverUri.resolve("token").toString())
                                     .set("jwks_uri", serverUri.resolve("jwks").toString())
                                     .set("end_session_endpoint", END_SESSION_ENDPOINT_URI.toString())
                                     .setStrings("response_types_supported", List.of("code"))
                                     .setStrings("code_challenge_methods_supported", List.of("S256"))
                                     .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                                     .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                                     .setStrings("grant_types_supported",
                                                 List.of("authorization_code", "client_credentials", "refresh_token"))
                                     .build().toString());
                tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken(NONCE, discoveryIssuer.toString())).toString();
                OidcTenantConfig tenant = OidcTenantConfig.builder(tenantConfig(serverUri,
                        code -> code.redirectionEndpointUri(URI.create("/oidc/callback"))))
                        .issuer(discoveryIssuer.toString())
                        .endpoints(endpoints -> endpoints.tlsRequired(false)
                                .wellKnownUri(discoveryIssuer.resolve("/.well-known/openid-configuration")))
                        .logout(config -> config.endSession(endSession -> endSession.idTokenHintRequired(false)))
                        .initializationMaxQueued(0).buildPrototype();
                try (OidcProvider provider = OidcProvider.create(providerConfig(tenant))) {
                    WebServer rp = WebServer.builder().port(0).addFeature(OidcFeature.create(provider)).build().start();
                    try {
                        WebClient client = WebClient.builder().baseUri(rpBaseUri(rp)).followRedirects(false).build();
                        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                            try {
                                Future<OidcTenantContext> leader = executor.submit(() -> provider.tenantRuntimeRegistry()
                                        .tenantContext("default").orElseThrow());
                                assertThat(entered.await(5, TimeUnit.SECONDS), is(true));
                                ProviderRequest request = OidcProviderTest.request(null, SecurityEnvironment.builder()
                                        .targetUri(URI.create("https://rp.example/resource")).build());
                                AuthenticationResponse authentication = provider.authenticate(request);
                                assertThat(authentication.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                                assertThat(authentication.statusCode().orElseThrow(), is(503));
                                assertThat(authentication.user().isEmpty(), is(true));
                                assertThat(authentication.responseHeaders().isEmpty(), is(true));
                                EndpointConfig outboundConfig = EndpointConfig.builder()
                                        .customObject(OidcOutboundPolicyConfig.class, OidcOutboundPolicyConfig.builder()
                                                .clientCredentialsGrantEnabled(true).buildPrototype())
                                        .build();
                                SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                                        .targetUri(URI.create("https://downstream.example/service")).build();
                                assertThat(provider.isOutboundSupported(request, outboundEnv, outboundConfig), is(true));
                                OutboundSecurityResponse outbound = provider.outboundSecurity(request, outboundEnv,
                                                                                               outboundConfig);
                                assertThat(outbound.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                                assertThat(outbound.description().orElseThrow(), is("OIDC tenant is unavailable"));
                                Thread.currentThread().interrupt();
                                try {
                                    assertThat(provider.authenticate(request).statusCode().orElseThrow(), is(503));
                                    assertThat(Thread.currentThread().isInterrupted(), is(true));
                                } finally {
                                    Thread.interrupted();
                                }

                                SetCookie state = authenticationRequestCookie("default", STATE,
                                                                               discoveryIssuer.toString(),
                                                                               callbackUri(rp), tenant);
                                SetCookie session = localAuthenticationCookie(
                                        tenant, "default", signedIdToken(NONCE, discoveryIssuer.toString()));
                                for (boolean recovering : List.of(false, true)) {
                                    if (recovering) {
                                        release.countDown();
                                        OidcTenantContext ready = leader.get(5, TimeUnit.SECONDS);
                                        assertThat(ready.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                                                   ready.ready(), is(true));
                                    }
                                    try (HttpClientResponse response = logout
                                            ? client.post("/oidc/logout").header(HeaderNames.ORIGIN, sameOrigin(rp))
                                                    .header(HeaderNames.COOKIE, session.name() + "=" + session.value()).request()
                                            : client.get("/oidc/callback").queryParam("state", STATE).queryParam("code", "code")
                                                    .header(HeaderNames.COOKIE, state.name() + "=" + state.value()).request()) {
                                        assertThat(response.status(),
                                                   is(recovering ? Status.SEE_OTHER_303 : Status.SERVICE_UNAVAILABLE_503));
                                        if (!recovering) {
                                            assertThat(response.headers().contains(HeaderNames.LOCATION), is(false));
                                            assertThat(response.as(String.class), containsString("temporarily unavailable"));
                                        }
                                        if (logout) {
                                            List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                                            assertRemovalCookie(cookies, tenant.cookies().localAuthenticationCookieName());
                                            assertRemovalCookie(cookies, tenant.cookies().authenticationRequestCookieName());
                                        } else if (recovering) {
                                            assertThat(localAuthenticationCookie(response, tenant).value().isEmpty(), is(false));
                                        } else {
                                            // The same state and code can still be redeemed after initialization finishes.
                                            assertThat(response.headers().contains(HeaderNames.SET_COOKIE), is(false));
                                        }
                                    }
                                    assertThat(TOKEN_REQUESTS.get(), is(recovering && !logout ? 1 : 0));
                                }
                                assertThat(discoveryRequests.get(), is(1));
                            } finally {
                                release.countDown();
                                client.closeResource();
                            }
                        }
                    } finally {
                        rp.stop();
                    }
                }
            } finally {
                release.countDown();
                discovery.stop();
            }
        }
    }

    @Test
    void jwksAdmissionFailuresReturn503ForIdTokenAndSignedUserInfoWithoutIssuingASession(URI serverUri) throws Exception {
        for (boolean signedUserInfo : List.of(false, true)) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            AtomicInteger requests = new AtomicInteger();
            JsonObject original = JsonParser.create(verifyJwkSet).readJsonObject();
            List<JsonValue> keys = new ArrayList<>(original.arrayValue("keys").orElseThrow().values());
            JsonObject rotatingKey = keys.stream().map(JsonValue::asObject)
                    .filter(key -> key.stringValue("kid").filter("verify-rsa"::equals).isPresent())
                    .findFirst().orElseThrow();
            keys.add(JsonObject.builder().from(rotatingKey).set("kid", "rotated-rsa").build());
            String rotatedKeys = JsonObject.builder().set("keys", JsonArray.create(keys)).build().toString();
            WebServer keyServer = WebServer.builder().port(0).routing(routing -> routing.get("/jwks", (_, response) -> {
                int request = requests.incrementAndGet();
                if (request == (signedUserInfo ? 2 : 1)) {
                    entered.countDown();
                    try {
                        if (!release.await(10, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Test did not release JWKS response");
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException(e);
                    }
                }
                response.header(HeaderValues.CONTENT_TYPE_JSON).send(request == 1 ? verifyJwkSet : rotatedKeys);
            })).build().start();
            URI keyUri = URI.create("http://localhost:" + keyServer.port() + "/jwks");
            OidcTenantConfig base = signedUserInfo
                    ? tenantConfigWithUserInfo(serverUri, keyUri, info -> info.jwt(jwt -> jwt.signingAlgorithm("RS256")))
                    : tenantConfig(serverUri);
            OidcTenantConfig tenant = OidcTenantConfig.builder(base)
                    .endpoints(OidcEndpointConfig.builder(base.endpoints()).jwksUri(keyUri).buildPrototype())
                    .authorizationCode(OidcAuthorizationCodeConfig.builder(base.authorizationCode().orElseThrow())
                                               .redirectionEndpointUri(URI.create("/oidc/callback")).buildPrototype())
                    .jwkSet(jwkSet -> jwkSet.maxQueued(0).unknownKeyIdRefreshInterval(Duration.ZERO)).buildPrototype();
            if (signedUserInfo) {
                userInfoEndpointContentType = "application/jwt";
                userInfoEndpointResponseBody = signedUserInfo("RS256", "rotated-rsa", SUBJECT, ISSUER.toString(),
                                                             CLIENT_ID, _ -> { });
            }
            try (OidcProvider provider = OidcProvider.create(providerConfig(tenant))) {
                WebServer rp = WebServer.builder().port(0).addFeature(OidcFeature.create(provider)).build().start();
                WebClient client = WebClient.builder().baseUri(rpBaseUri(rp)).followRedirects(false).build();
                try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                    OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("default").orElseThrow();
                    assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                               context.ready(), is(true));
                    OidcJwkSetManager manager = context.jwkSetManager();
                    if (signedUserInfo) {
                        manager.jwkKeys();
                    }
                    Future<?> leader = executor.submit(() -> signedUserInfo
                            ? manager.jwkKeys(Optional.of("rotated-rsa"))
                            : manager.jwkKeys());
                    try {
                        assertThat(entered.await(5, TimeUnit.SECONDS), is(true));
                        SetCookie state = authenticationRequestCookie(callbackUri(rp), tenant);
                        try (HttpClientResponse response = client.get("/oidc/callback").queryParam("state", STATE)
                                .queryParam("code", "first-code")
                                .header(HeaderNames.COOKIE, state.name() + "=" + state.value()).request()) {
                            assertThat(response.status(), is(Status.SERVICE_UNAVAILABLE_503));
                            assertThat(response.as(String.class), containsString("temporarily unavailable"));
                            assertNoLocalAuthenticationCookie(response, tenant);
                        }
                        assertThat(requests.get(), is(signedUserInfo ? 2 : 1));
                        release.countDown();
                        leader.get(5, TimeUnit.SECONDS);
                        // Start a new authentication transaction; do not retry a consumed authorization code.
                        String freshState = authorizationState("default", 99);
                        SetCookie freshCookie = authenticationRequestCookie("default", freshState, ISSUER.toString(),
                                                                            callbackUri(rp), tenant);
                        try (HttpClientResponse response = client.get("/oidc/callback").queryParam("state", freshState)
                                .queryParam("code", "new-code")
                                .header(HeaderNames.COOKIE, freshCookie.name() + "=" + freshCookie.value()).request()) {
                            assertThat(response.status(), is(Status.SEE_OTHER_303));
                            assertThat(localAuthenticationCookie(response, tenant).value().isEmpty(), is(false));
                        }
                    } finally {
                        release.countDown();
                        client.closeResource();
                        rp.stop();
                    }
                }
            } finally {
                release.countDown();
                keyServer.stop();
            }
        }
    }

    @Test
    void providerAndFeatureReuseOnePrivateKeyJwtConfiguration(URI serverUri) {
        OidcTenantConfig tenant = OidcTenantConfig.builder(tenantConfig(serverUri,
                                                                      authorization -> authorization.redirectionEndpointUri(
                                                                              URI.create("/oidc/callback"))))
                .clearClientSecret()
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertion(assertion -> assertion.jwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-sign-jwk.json")
                        .buildPrototype())
                        .keyId("sign-rsa")
                        .algorithm("RS256"))
                .buildPrototype();
        OidcProviderConfig config = providerConfig(tenant);
        OidcProvider provider = OidcProvider.create(config);
        WebServer rp = oidcFeatureServer(config);
        WebClient client = WebClient.builder().baseUri(rpBaseUri(rp)).build();
        try {
            URI resourceUri = rpBaseUri(rp).resolve("/resource");
            AuthenticationResponse login = provider.authenticate(OidcProviderTest.request(null,
                                                                                         SecurityEnvironment.builder()
                                                                                                 .targetUri(resourceUri)
                                                                                                 .build()));
            UriQuery authorization = UriQuery.create(URI.create(login.responseHeaders().get("Location").getFirst()));
            assertThat(authorization.first("redirect_uri").orElseThrow(), is(callbackUri(rp).toString()));
            tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken(authorization.first("nonce").orElseThrow()))
                    .toString();
            String initialCookies = String.join("; ", login.responseHeaders().get("Set-Cookie").stream()
                    .map(SetCookie::parse)
                    .map(cookie -> cookie.name() + "=" + cookie.value())
                    .toList());

            try (HttpClientResponse callback = client.get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "authorization-code")
                    .queryParam("state", authorization.first("state").orElseThrow())
                    .header(HeaderNames.COOKIE, initialCookies)
                    .request()) {
                assertThat(callback.status(), is(Status.SEE_OTHER_303));
                SignedJwt assertion = SignedJwt.parseToken(TOKEN_CLIENT_ASSERTION.get());
                assertion.verifySignature(signKeys).checkValid();
                assertThat(assertion.getJwt().issuer().orElseThrow(), is(CLIENT_ID));
                assertThat(assertion.getJwt().subject().orElseThrow(), is(CLIENT_ID));
                assertThat(assertion.getJwt().audience().orElseThrow(), is(List.of(serverUri.resolve("token").toString())));
                SetCookie authenticationCookie = callback.headers().get(HeaderNames.SET_COOKIE).allValues().stream()
                        .map(SetCookie::parse)
                        .filter(cookie -> cookie.name().equals(tenant.cookies().localAuthenticationCookieName()))
                        .findFirst()
                        .orElseThrow();
                AuthenticationResponse authenticated = provider.authenticate(OidcProviderTest.request(null,
                        SecurityEnvironment.builder()
                                .targetUri(resourceUri)
                                .header(HeaderNames.COOKIE.defaultCase(), initialCookies + "; "
                                        + authenticationCookie.name() + "=" + authenticationCookie.value())
                                .build()));

                assertThat(authenticated.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                assertThat(authenticated.user().orElseThrow().principal().id(), is(issuerSubjectPrincipalId()));
            }
        } finally {
            client.closeResource();
            rp.stop();
        }
    }

    @Test
    void chunkedStateCompletesCallbackRestoresFullUriAndIsRemovedOnLogout(URI serverUri) {
        for (boolean customState : List.of(false, true)) {
            OidcTenantConfig.Builder tenantBuilder = OidcTenantConfig.builder(tenantConfig(serverUri,
                    code -> code.redirectionEndpointUri(URI.create("/oidc/callback"))))
                    .logout(_ -> { });
            if (customState) {
                tenantBuilder.adapter(new OidcTenantAdapter() {
                    @Override
                    public String name() {
                        return "chunked-state-test";
                    }

                    @Override
                    public String type() {
                        return "chunked-state-test";
                    }

                    @Override
                    public OidcAuthorizationParameters authorizationRequest(OidcTenantConfig tenant,
                                                                            String tenantId,
                                                                            SecurityEnvironment environment,
                                                                            OidcAuthorizationParameters parameters) {
                        OidcAuthorizationParameters.Builder values = OidcAuthorizationParameters.builder(parameters);
                        values.putParameter("state", List.of(JsonString.create("custom-state")));
                        return values.buildPrototype();
                    }
                });
            }
            OidcTenantConfig tenant = tenantBuilder.buildPrototype();
            OidcProviderConfig config = OidcProviderConfig.builder().putTenant("chunked", tenant).buildPrototype();
            try (OidcProvider provider = OidcProvider.create(config)) {
                WebServer rp = WebServer.builder().host("127.0.0.1").port(0)
                        .addFeature(OidcFeature.create(provider)).build().start();
                WebClient client = WebClient.builder().baseUri(rpBaseUri(rp)).build();
                try {
                    URI original = URI.create(rpBaseUri(rp) + "/resource?filter=" + "a".repeat(3000));
                    AuthenticationResponse login = provider.authenticate(OidcProviderTest.request(null,
                            SecurityEnvironment.builder().targetUri(original).transport("http").build()));
                    assertThat(login.statusCode().orElseThrow(), is(303));
                    UriQuery authorization = UriQuery.create(URI.create(login.responseHeaders().get("Location").getFirst()));
                    tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken(authorization.get("nonce"))).toString();
                    String stateName = tenant.cookies().authenticationRequestCookieName();
                    List<SetCookie> stateCookies = login.responseHeaders().get("Set-Cookie").stream()
                            .map(SetCookie::parse)
                            .filter(cookie -> !cookie.name().endsWith("-generation"))
                            .toList();
                    assertThat(stateCookies, hasSize(greaterThan(1)));
                    Map<String, List<String>> browserCookies = new LinkedHashMap<>();
                    login.responseHeaders().get("Set-Cookie").stream().map(SetCookie::parse)
                            .forEach(cookie -> browserCookies.put(cookie.name(), List.of(cookie.value())));
                    String initialCookies = String.join("; ", browserCookies.entrySet().stream()
                            .map(entry -> entry.getKey() + "=" + entry.getValue().getFirst()).toList());
                    int tokenRequests = TOKEN_REQUESTS.get();
                    String incompleteCookies = String.join("; ", browserCookies.entrySet().stream()
                            .filter(entry -> !entry.getKey().equals(stateName + ".1"))
                            .map(entry -> entry.getKey() + "=" + entry.getValue().getFirst()).toList());
                    try (HttpClientResponse callback = client.get("/oidc/callback").followRedirects(false)
                            .queryParam("code", "authorization-code").queryParam("state", authorization.get("state"))
                            .header(HeaderNames.COOKIE, incompleteCookies).request()) {
                        assertThat(callback.status(), is(Status.BAD_REQUEST_400));
                        assertThat(TOKEN_REQUESTS.get(), is(tokenRequests));
                        assertThat(callback.headers().first(HeaderNames.SET_COOKIE), is(Optional.empty()));
                    }
                    try (HttpClientResponse callback = client.get("/oidc/callback").followRedirects(false)
                            .queryParam("code", "authorization-code").queryParam("state", authorization.get("state"))
                            .header(HeaderNames.COOKIE, initialCookies).request()) {
                        assertThat(callback.status(), is(Status.SEE_OTHER_303));
                        assertThat(rpBaseUri(rp).resolve(callback.headers().get(HeaderNames.LOCATION).get()), is(original));
                        assertThat(TOKEN_REQUESTS.get(), is(tokenRequests + 1));
                        List<String> updates = callback.headers().get(HeaderNames.SET_COOKIE).allValues();
                        stateCookies.forEach(cookie -> assertRemovalCookie(updates, cookie.name()));
                        updates.stream().map(SetCookie::parse).forEach(cookie -> {
                            if (cookie.value().isEmpty()) {
                                browserCookies.remove(cookie.name());
                            } else {
                                browserCookies.put(cookie.name(), List.of(cookie.value()));
                            }
                        });
                    }
                    String storedCookies = String.join("; ", browserCookies.entrySet().stream()
                            .map(entry -> entry.getKey() + "=" + entry.getValue().getFirst()).toList());
                    AuthenticationResponse stored = provider.authenticate(OidcProviderTest.request(null,
                            SecurityEnvironment.builder().targetUri(original).transport("http")
                                    .header(HeaderNames.COOKIE.defaultCase(), storedCookies).build()));
                    assertThat(stored.status(), is(SecurityResponse.SecurityStatus.SUCCESS));

                    // A pending login may coexist with a session; logout must clear observed orphaned pieces too.
                    String pendingCookies = String.join("; ", stateCookies.stream().skip(1)
                            .map(cookie -> cookie.name() + "=" + cookie.value()).toList());
                    try (HttpClientResponse logout = client.post("/oidc/logout")
                            .header(HeaderNames.ORIGIN, sameOrigin(rp))
                            .header(HeaderNames.COOKIE, storedCookies + "; " + pendingCookies + "; " + stateName + ".15=orphan")
                            .request()) {
                        assertThat(logout.status(), is(Status.NO_CONTENT_204));
                        List<String> updates = logout.headers().get(HeaderNames.SET_COOKIE).allValues();
                        stateCookies.forEach(cookie -> assertRemovalCookie(updates, cookie.name()));
                        assertRemovalCookie(updates, stateName + ".15");
                    }
                } finally {
                    client.closeResource();
                    rp.stop();
                }
            }
        }
    }

    @Test
    void redirectionEndpointUsesConfiguredRequestScopesWhenScopeOmitted(URI serverUri) {
        assertCallbackScopes(serverUri, Optional.empty(), Optional.empty(), List.of("openid", "accounts.write"));
    }

    @Test
    void redirectionEndpointUsesAdapterNarrowedRequestScopesWhenScopeOmitted(URI serverUri) {
        assertCallbackScopes(serverUri, Optional.of("openid"), Optional.empty(), List.of("openid"));
    }

    @Test
    void redirectionEndpointUsesAdapterAddedRequestScopesWhenScopeOmitted(URI serverUri) {
        assertCallbackScopes(serverUri, Optional.of("openid email"), Optional.empty(), List.of("openid", "email"));
    }

    @Test
    void redirectionEndpointPrefersTokenResponseScopeOverAdapterRequestScopes(URI serverUri) {
        assertCallbackScopes(serverUri, Optional.of("openid email"), Optional.of("openid"), List.of("openid"));
    }

    @Test
    void callbackSubjectMappingFailureRejectsSessionAndClearsPreviousChunks(URI serverUri) {
        AtomicInteger mappings = new AtomicInteger();
        AtomicReference<UnaryOperator<Subject>> mapping = new AtomicReference<>();
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "callback-subject-test";
            }

            @Override
            public String type() {
                return "callback-subject-test";
            }

            @Override
            public Subject mapSubject(OidcTenantConfig tenant, Subject subject) {
                mappings.incrementAndGet();
                return mapping.get().apply(subject);
            }
        };
        OidcTenantConfig tenant = OidcTenantConfig.builder(tenantConfig(serverUri))
                .adapter(adapter)
                .cookies(cookies -> cookies.compression(OidcCookieCompression.NONE)
                        .protection(protection -> protection.password(COOKIE_PASSWORD)))
                .buildPrototype();
        OidcCookieStateHandler cookieHandler = OidcCookieStateHandler.create("default", tenant);
        String sessionCookieName = tenant.cookies().localAuthenticationCookieName();
        Instant now = Instant.now();
        SignedJwt idToken = SignedJwt.parseToken(signedIdToken(NONCE));
        OidcLocalAuthenticationResult previousSession = OidcLocalAuthenticationResult.fromStoredValues(
                OidcLocalAuthenticationState.builder()
                        .tenantId("default")
                        .idToken(new OidcValidatedIdToken(idToken.tokenContent(), false, idToken, idToken.getJwt()))
                        .accessToken("a".repeat(2500))
                        .tokenType("Bearer")
                        .scope("openid profile")
                        .createdAt(now)
                        .expiresAt(now.plusSeconds(600))
                        .accessTokenExpiresAt(now.plusSeconds(600))
                        .buildPrototype());
        List<SetCookie> previousCookies = cookieHandler.createLocalAuthenticationResultCookies(previousSession, Map.of(), now);
        assertThat(previousCookies, hasSize(greaterThan(1)));
        List<Map.Entry<String, UnaryOperator<Subject>>> failures = List.of(
                Map.entry("rejected", _ -> {
                    throw new IllegalArgumentException("Disabled user: private mapping details");
                }),
                Map.entry("unavailable", _ -> {
                    throw new IllegalStateException("Private mapping backend failure");
                }),
                Map.entry("null-subject", _ -> null));

        try (OidcProvider provider = OidcProvider.create(providerConfig(tenant))) {
            WebClient client = WebClient.create();
            try {
                WebServer rp = WebServer.builder().host("127.0.0.1").port(0)
                        .addFeature(OidcFeature.create(provider)).build().start();
                try {
                    for (boolean existingSession : List.of(false, true)) {
                        for (Map.Entry<String, UnaryOperator<Subject>> failure : failures) {
                            mapping.set(failure.getValue());
                            int mappingsBefore = mappings.get();
                            SetCookie state = authenticationRequestCookie(callbackUri(rp), tenant);
                            List<SetCookie> incoming = new ArrayList<>(existingSession ? previousCookies : List.of());
                            incoming.add(state);
                            String cookieHeader = String.join("; ", incoming.stream()
                                    .map(cookie -> cookie.name() + "=" + cookie.value()).toList());
                            try (HttpClientResponse callback = client.get().uri(callbackUri(rp)).followRedirects(false)
                                    .queryParam("code", failure.getKey() + "-code-" + existingSession)
                                    .queryParam("state", STATE)
                                    .header(HeaderNames.COOKIE, cookieHeader).request()) {
                                List<String> cookies = callback.headers().get(HeaderNames.SET_COOKIE).allValues();
                                List<String> liveSessionNames = cookies.stream().map(SetCookie::parse)
                                        .filter(cookie -> (cookie.name().equals(sessionCookieName)
                                                || cookie.name().startsWith(sessionCookieName + "."))
                                                && !cookie.value().isEmpty())
                                        .map(SetCookie::name).toList();
                                assertAll(failure.getKey() + ", existing session=" + existingSession,
                                          () -> assertThat(callback.status(), is(Status.SERVICE_UNAVAILABLE_503)),
                                          () -> assertThat(mappings.get(), is(mappingsBefore + 1)),
                                          () -> assertThat(liveSessionNames, empty()),
                                          () -> assertThat(callback.as(String.class), is("OIDC subject mapping failed")),
                                          () -> {
                                              assertRemovalCookie(cookies, tenant.cookies().authenticationRequestCookieName());
                                              assertRemovalCookie(cookies, sessionCookieName);
                                              if (existingSession) {
                                                  previousCookies.forEach(cookie -> assertRemovalCookie(cookies, cookie.name()));
                                              }
                                          });
                            }
                        }
                    }
                } finally {
                    rp.stop();
                }
            } finally {
                client.closeResource();
            }
        }
    }

    @Test
    void callbackMapsValidatedSubjectBeforeStorageAndMapsStoredSessionAgain(URI serverUri) {
        AtomicInteger mappings = new AtomicInteger();
        AtomicReference<Subject> mapped = new AtomicReference<>();
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "callback-subject-test";
            }

            @Override
            public String type() {
                return "callback-subject-test";
            }

            @Override
            public Subject mapSubject(OidcTenantConfig tenant, Subject subject) {
                mappings.incrementAndGet();
                mapped.set(subject);
                return Subject.builder().update(subject).addGrant(Role.create("mapped")).build();
            }
        };
        userInfoEndpointResponseBody = userInfoEndpointResponse(SUBJECT)
                .set("preferred_username", "userinfo-user").setStrings("groups", List.of("admin")).build().toString();
        OidcTenantConfig tenant = OidcTenantConfig.builder(tenantConfigWithUserInfo(serverUri))
                .adapter(adapter).buildPrototype();
        try (OidcProvider provider = OidcProvider.create(providerConfig(tenant))) {
            WebClient client = WebClient.create();
            try {
                WebServer rp = WebServer.builder().host("127.0.0.1").port(0)
                        .addFeature(OidcFeature.create(provider)).build().start();
                try {
                    SetCookie state = authenticationRequestCookie(callbackUri(rp), tenant);
                    try (HttpClientResponse callback = client.get().uri(callbackUri(rp)).followRedirects(false)
                            .queryParam("code", "authorization-code").queryParam("state", STATE)
                            .header(HeaderNames.COOKIE, state.name() + "=" + state.value()).request()) {
                        assertThat(callback.status(), is(Status.SEE_OTHER_303));
                        assertThat(mappings.get(), is(1));
                        Subject callbackSubject = mapped.get();
                        assertThat(callbackSubject.principal().id(), is(issuerSubjectPrincipalId()));
                        assertThat(callbackSubject.principal().getName(), is("userinfo-user"));
                        assertThat(callbackSubject.publicCredential(TokenCredential.class).orElseThrow().token(),
                                   is("access-token"));
                        assertThat(callbackSubject.grantsByType("scope").stream().map(Grant::getName).toList(),
                                   containsInAnyOrder("openid", "profile"));
                        assertThat(callbackSubject.grants(Role.class).stream().map(Role::getName).toList(),
                                   containsInAnyOrder("admin"));
                        SetCookie session = localAuthenticationCookie(callback, tenant);
                        AuthenticationResponse authentication = provider.authenticate(OidcProviderTest.request(null,
                                SecurityEnvironment.builder().targetUri(rpBaseUri(rp).resolve("/resource"))
                                        .header(HeaderNames.COOKIE.defaultCase(), session.name() + "=" + session.value())
                                        .build()));
                        assertThat(authentication.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                        assertThat(mappings.get(), is(2));
                        assertThat(authentication.user().orElseThrow().grants(Role.class).stream().map(Role::getName).toList(),
                                   containsInAnyOrder("admin", "mapped"));
                    }
                } finally {
                    rp.stop();
                }
            } finally {
                client.closeResource();
            }
        }
    }

    @Test
    void callbackDoesNotMapUnvalidatedIdTokenOrUserInfo(URI serverUri) {
        AtomicInteger mappings = new AtomicInteger();
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "callback-subject-test";
            }

            @Override
            public String type() {
                return "callback-subject-test";
            }

            @Override
            public Subject mapSubject(OidcTenantConfig tenant, Subject subject) {
                mappings.incrementAndGet();
                return subject;
            }
        };
        OidcTenantConfig tenant = OidcTenantConfig.builder(tenantConfigWithUserInfo(serverUri))
                .adapter(adapter).buildPrototype();
        try (OidcProvider provider = OidcProvider.create(providerConfig(tenant))) {
            WebClient client = WebClient.create();
            try {
                WebServer rp = WebServer.builder().host("127.0.0.1").port(0)
                        .addFeature(OidcFeature.create(provider)).build().start();
                try {
                    for (boolean invalidIdToken : List.of(true, false)) {
                        tokenEndpointResponseBody = tokenEndpointResponse(invalidIdToken
                                ? tamperedSignature(signedIdToken(NONCE)) : signedIdToken(NONCE)).toString();
                        userInfoEndpointResponseBody = userInfoEndpointResponse(invalidIdToken ? SUBJECT : "other-user")
                                .build().toString();
                        SetCookie state = authenticationRequestCookie(callbackUri(rp), tenant);
                        try (HttpClientResponse callback = client.get().uri(callbackUri(rp)).followRedirects(false)
                                .queryParam("code", "invalid-claims-code-" + invalidIdToken).queryParam("state", STATE)
                                .header(HeaderNames.COOKIE, state.name() + "=" + state.value()).request()) {
                            assertThat(callback.status(), is(Status.BAD_GATEWAY_502));
                            assertThat(mappings.get(), is(0));
                            assertNoLocalAuthenticationCookie(callback, tenant);
                        }
                    }
                } finally {
                    rp.stop();
                }
            } finally {
                client.closeResource();
            }
        }
    }

    @Test
    void storedSessionMappingRejectionAfterRefreshRemovesCookies(URI serverUri) {
        AtomicInteger mappings = new AtomicInteger();
        AtomicReference<Subject> mapped = new AtomicReference<>();
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "refreshed-subject-test";
            }

            @Override
            public String type() {
                return "refreshed-subject-test";
            }

            @Override
            public Subject mapSubject(OidcTenantConfig tenant, Subject subject) {
                mappings.incrementAndGet();
                mapped.set(subject);
                throw new IllegalArgumentException("User disabled after refresh");
            }
        };
        OidcTenantConfig tenant = OidcTenantConfig.builder(tenantConfig(serverUri))
                .adapter(adapter).buildPrototype();
        tokenEndpointResponseBody = JsonObject.builder().set("access_token", "refreshed-access-token")
                .set("token_type", "Bearer").set("expires_in", 600).set("scope", "openid").build().toString();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SignedJwt idToken = SignedJwt.sign(Jwt.builder().type("JWT").algorithm("RS256").keyId("verify-rsa")
                .issuer(ISSUER.toString()).subject(SUBJECT).addAudience(CLIENT_ID).nonce(NONCE)
                .issueTime(now.minusSeconds(600)).expirationTime(now.plusSeconds(3000)).build(),
                                          signKeys.forKeyId("sign-rsa").orElseThrow());
        OidcLocalAuthenticationResult session = OidcLocalAuthenticationResult.fromStoredValues(
                OidcLocalAuthenticationState.builder()
                        .tenantId("default")
                        .idToken(new OidcValidatedIdToken(idToken.tokenContent(), false, idToken, idToken.getJwt()))
                        .accessToken("expired-access-token")
                        .refreshToken("refresh-token")
                        .tokenType("Bearer")
                        .scope("openid profile")
                        .createdAt(now.minusSeconds(600))
                        .expiresAt(now.plusSeconds(3000))
                        .accessTokenExpiresAt(now.minusSeconds(1))
                        .buildPrototype());
        List<SetCookie> currentCookies = OidcCookieStateHandler.create("default", tenant)
                .createLocalAuthenticationResultCookies(session, Map.of(), now);
        String cookieHeader = String.join("; ", currentCookies.stream()
                .map(cookie -> cookie.name() + "=" + cookie.value()).toList());
        try (OidcProvider provider = OidcProvider.create(providerConfig(tenant))) {
            AuthenticationResponse rejected = provider.authenticate(OidcProviderTest.request(null,
                    SecurityEnvironment.builder().targetUri(URI.create("https://rp.example/resource"))
                            .header(HeaderNames.COOKIE.defaultCase(), cookieHeader).build()));
            assertThat(rejected.status(), is(SecurityResponse.SecurityStatus.FAILURE));
            assertThat(rejected.statusCode().orElseThrow(), is(503));
            assertThat(TOKEN_REQUESTS.get(), is(1));
            assertThat(mappings.get(), is(1));
            assertThat(mapped.get().publicCredential(TokenCredential.class).orElseThrow().token(),
                       is("refreshed-access-token"));
            assertThat(mapped.get().grantsByType("scope").stream().map(Grant::getName).toList(),
                       containsInAnyOrder("openid"));
            List<String> removed = rejected.responseHeaders().getOrDefault(HeaderNames.SET_COOKIE.defaultCase(), List.of());
            currentCookies.forEach(cookie -> assertRemovalCookie(removed, cookie.name()));
            removed.stream().map(SetCookie::parse).forEach(cookie -> assertThat(cookie.value(), is("")));
        }
    }

    @Test
    void redirectionEndpointRouteValidatesIdToken(URI serverUri) {
        WebServer rpServer = oidcFeatureServer(providerConfig(serverUri));
        try {
            URI callbackUri = callbackUri(rpServer);
            OidcTenantConfig tenant = tenantConfig(serverUri);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);
            Instant beforeCallback = Instant.now();

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
                assertThat(response.headers().first(HeaderNames.LOCATION).orElse(""),
                           is("/resource"));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.stream()
                                   .anyMatch(cookie -> cookie.startsWith(tenant.cookies()
                                                                                 .localAuthenticationCookieName()
                                                                         + "=")),
                           is(true));
                assertThat(cookies.stream()
                                   .anyMatch(cookie -> cookie.startsWith(tenant.cookies()
                                                                                 .authenticationRequestCookieName()
                                                                         + "=")
                                           && cookie.contains("Expires=")),
                           is(true));

                SetCookie localAuthenticationCookie = SetCookie.parse(cookies.stream()
                        .filter(cookie -> cookie.startsWith(tenant.cookies().localAuthenticationCookieName() + "="))
                        .findFirst()
                        .orElseThrow());
                AuthenticationResponse authentication = OidcProvider.create(providerConfig(serverUri))
                        .authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                                .targetUri(URI.create("https://rp.example/resource"))
                                .header(HeaderNames.COOKIE.defaultCase(),
                                        localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                                .build()));

                assertThat(authentication.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                Subject subject = authentication.user().orElseThrow();
                assertThat(subject.principal().id(), is(issuerSubjectPrincipalId()));
                assertThat(subject.principal().getName(), is(USERNAME));
                assertThat(subject.principal().abacAttributeRaw("email"), is(EMAIL));
                assertThat(subject.grantsByType("scope").stream().map(Grant::getName).toList(),
                           is(List.of("openid", "profile")));

                TokenCredential credential = subject.publicCredential(TokenCredential.class).orElseThrow();
                assertThat(credential.token(), is("access-token"));
                assertThat(credential.getIssuer().orElse(""), is(ISSUER.toString()));
                Instant accessTokenExpiresAt = credential.getExpTime().orElseThrow();
                assertThat(!accessTokenExpiresAt.isBefore(beforeCallback.plusSeconds(600)), is(true));
                assertThat(!accessTokenExpiresAt.isAfter(Instant.now().plusSeconds(600)), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRejectsUnusableAccessTokenLifetimesBeforeUserInfo(URI serverUri) {
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri);
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        WebClient client = WebClient.builder().baseUri(rpBaseUri(rpServer)).build();
        try {
            for (String lifetime : List.of("0", "-1", "1.5", "9223372036854775808")) {
                tokenEndpointResponseBody = JsonObject.builder()
                        .from(tokenEndpointResponse(signedIdToken(NONCE)))
                        .set("expires_in", new BigDecimal(lifetime))
                        .build()
                        .toString();
                SetCookie stateCookie = authenticationRequestCookie(callbackUri(rpServer), tenant);
                try (HttpClientResponse response = client.get("/oidc/callback")
                        .followRedirects(false)
                        .queryParam("code", "authorization-code")
                        .queryParam("state", STATE)
                        .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                        .request()) {
                    assertThat("expires_in=" + lifetime, response.status(), is(Status.BAD_GATEWAY_502));
                    assertThat(response.as(String.class), is("Token Endpoint exchange failed"));
                    assertThat(response.headers().get(HeaderNames.SET_COOKIE).allValues().stream()
                                       .map(SetCookie::parse)
                                       .anyMatch(cookie -> cookie.name().equals(tenant.cookies().localAuthenticationCookieName())),
                               is(false));
                    assertThat(USER_INFO_AUTHORIZATION.get(), is(""));
                }
            }
        } finally {
            client.closeResource();
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointPreservesOmittedShortAndVeryLargeLifetimes(URI serverUri) {
        OidcTenantConfig tenant = tenantConfig(serverUri);
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        WebClient client = WebClient.builder().baseUri(rpBaseUri(rpServer)).build();
        try {
            for (Optional<Long> lifetime : List.of(Optional.<Long>empty(), Optional.of(1L), Optional.of(60L),
                                                  Optional.of(Instant.MAX.getEpochSecond()), Optional.of(Long.MAX_VALUE))) {
                JsonObject.Builder json = JsonObject.builder()
                        .from(tokenEndpointResponse(signedIdToken(NONCE)))
                        .unset("expires_in");
                lifetime.ifPresent(seconds -> json.set("expires_in", seconds));
                tokenEndpointResponseBody = json.build().toString();
                SetCookie stateCookie = authenticationRequestCookie(callbackUri(rpServer), tenant);
                Instant beforeCallback = Instant.now();
                try (HttpClientResponse response = client.get("/oidc/callback")
                        .followRedirects(false)
                        .queryParam("code", "authorization-code")
                        .queryParam("state", STATE)
                        .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                        .request()) {
                    assertThat("expires_in=" + lifetime, response.status(), is(Status.SEE_OTHER_303));
                    SetCookie cookie = response.headers().get(HeaderNames.SET_COOKIE).allValues().stream()
                            .map(SetCookie::parse)
                            .filter(it -> it.name().equals(tenant.cookies().localAuthenticationCookieName()))
                            .findFirst()
                            .orElseThrow();
                    OidcLocalAuthenticationResult stored = OidcCookieStateHandler.create("default", tenant)
                            .decodeLocalAuthenticationResult(cookie.value(), OidcIdTokenDecryptor.create(tenant))
                            .orElseThrow();
                    if (lifetime.isEmpty()) {
                        assertThat(stored.accessTokenExpiresAt(), is(Optional.empty()));
                    } else if (lifetime.orElseThrow() > 60) {
                        assertThat(stored.accessTokenExpiresAt(), is(Optional.of(Instant.MAX)));
                    } else {
                        Instant expiry = stored.accessTokenExpiresAt().orElseThrow();
                        assertThat(expiry, greaterThanOrEqualTo(beforeCallback.plusSeconds(lifetime.orElseThrow())));
                        assertThat(expiry, lessThanOrEqualTo(stored.createdAt().plusSeconds(lifetime.orElseThrow())));
                    }
                    assertThat(stored.expiresAt(), is(stored.idToken().jwt().expirationTime().orElseThrow()));
                    assertThat(stored.expiresAt().isAfter(stored.createdAt()), is(true));
                }
            }
        } finally {
            client.closeResource();
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointStoresLargeSessionsWithGenericCookiePolicies(URI serverUri) {
        for (OidcCookieCompression compression : OidcCookieCompression.values()) {
            String accessToken = "a".repeat(compression == OidcCookieCompression.GZIP ? 24000 : 6000);
            tokenEndpointResponseBody = JsonObject.builder()
                    .from(tokenEndpointResponse(signedIdToken(NONCE)))
                    .set("access_token", accessToken)
                    .set("refresh_token", "r".repeat(500))
                    .build().toString();
            OidcTenantConfig original = tenantConfig(serverUri);
            OidcTenantConfig tenant = OidcTenantConfig.builder(original)
                    .cookies(OidcCookieConfig.builder(original.cookies()).compression(compression).buildPrototype())
                    .buildPrototype();
            WebServer rp = oidcFeatureServer(providerConfig(tenant));
            WebClient client = WebClient.builder().baseUri(rpBaseUri(rp)).build();
            try {
                SetCookie stateCookie = authenticationRequestCookie(callbackUri(rp), tenant);
                try (HttpClientResponse response = client.get("/oidc/callback")
                        .followRedirects(false).queryParam("code", "authorization-code").queryParam("state", STATE)
                        .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value()).request()) {
                    assertThat(response.status(), is(Status.SEE_OTHER_303));
                    String base = tenant.cookies().localAuthenticationCookieName();
                    List<SetCookie> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues().stream()
                            .map(SetCookie::parse)
                            .filter(cookie -> cookie.name().equals(base) || cookie.name().startsWith(base + "."))
                            .toList();
                    assertThat(cookies.size() > 1, is(compression == OidcCookieCompression.NONE));
                    cookies.forEach(cookie -> assertThat(cookie.toString().length() <= tenant.cookies().maxCookieSize(), is(true)));
                    String cookieHeader = String.join("; ", cookies.stream()
                            .map(cookie -> cookie.name() + "=" + cookie.value()).toList());
                    AuthenticationResponse authentication = OidcProvider.create(providerConfig(tenant))
                            .authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                                    .targetUri(URI.create("https://rp.example/resource"))
                                    .header(HeaderNames.COOKIE.defaultCase(), cookieHeader).build()));
                    assertThat(authentication.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                    assertThat(authentication.user().orElseThrow().publicCredential(TokenCredential.class)
                                       .orElseThrow().token(), is(accessToken));
                }
            } finally {
                client.closeResource();
                rp.stop();
            }
        }
    }

    @Test
    void redirectionEndpointFailsCleanlyWhenSessionCannotFit(URI serverUri) {
        tokenEndpointResponseBody = JsonObject.builder()
                .from(tokenEndpointResponse(signedIdToken(NONCE)))
                .set("access_token", "a".repeat(24000)).build().toString();
        OidcTenantConfig tenant = tenantConfig(serverUri);
        WebServer rp = oidcFeatureServer(providerConfig(tenant));
        WebClient client = WebClient.builder().baseUri(rpBaseUri(rp)).build();
        try {
            SetCookie stateCookie = authenticationRequestCookie(callbackUri(rp), tenant);
            try (HttpClientResponse response = client.get("/oidc/callback")
                    .followRedirects(false).queryParam("code", "authorization-code").queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value()).request()) {
                assertThat(response.status(), is(Status.SERVICE_UNAVAILABLE_503));
                assertThat(response.headers().contains(HeaderNames.LOCATION), is(false));
                assertThat(response.as(String.class), is("OIDC session cannot be stored within the configured cookie limits"));
                List<SetCookie> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues().stream()
                        .map(SetCookie::parse).toList();
                assertThat(cookies.size(), is(17));
                cookies.forEach(cookie -> {
                    assertThat(cookie.value(), is(""));
                    assertThat(cookie.expires().orElseThrow().toInstant(), is(Instant.EPOCH));
                });
            }
        } finally {
            client.closeResource();
            rp.stop();
        }
    }

    @Test
    void redirectionEndpointRouteUsesRequestedUriDiscoveryBehindReverseProxy(URI serverUri) {
        URI externalOriginalUri = URI.create("https://app.example/external/resource");
        URI externalCallbackUri = URI.create("https://app.example/external/oidc/callback");
        OidcTenantConfig tenant = tenantConfig(serverUri, authorizationCode -> authorizationCode
                .redirectionEndpointUri(URI.create("/oidc/callback")));
        WebServer rpServer = oidcFeatureServerWithRequestedUriDiscovery(providerConfig(tenant));
        try {
            SetCookie stateCookie = authenticationRequestCookie(externalCallbackUri, tenant, externalOriginalUri);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.X_FORWARDED_HOST, "app.example")
                    .header(HeaderNames.X_FORWARDED_PROTO, "https")
                    .header(HeaderNames.X_FORWARDED_PREFIX, "/external")
                    .header(HeaderNames.X_FORWARDED_FOR, "client.example,proxy.example")
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
                assertThat(response.headers().first(HeaderNames.LOCATION).orElse(""),
                           is("/external/resource"));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsInvalidIdToken(URI serverUri) {
        tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken("other-nonce")).toString();
        WebServer rpServer = oidcFeatureServer(providerConfig(serverUri));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenantConfig(serverUri));

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("ID Token is invalid"));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsCriticalEncryptedIdToken(URI serverUri) throws Exception {
        OidcTenantConfig tenant = OidcTenantConfig.builder(tenantConfig(serverUri))
                .idToken(config -> config.decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype()))
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            for (List<String> critical : List.of(List.of("extension"), List.<String>of())) {
                String encrypted = OidcTestJwe.encrypt(signedIdToken(NONCE),
                                                       encryptKeys,
                                                       true,
                                                       JsonObject.builder()
                                                               .setStrings("crit", critical)
                                                               .set("extension", true)
                                                               .build());
                tokenEndpointResponseBody = tokenEndpointResponse(encrypted).toString();
                SetCookie stateCookie = authenticationRequestCookie(callbackUri(rpServer), tenant);

                try (HttpClientResponse response = WebClient.builder()
                        .baseUri(rpBaseUri(rpServer))
                        .build()
                        .get("/oidc/callback")
                        .followRedirects(false)
                        .queryParam("code", "authorization-code")
                        .queryParam("state", STATE)
                        .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                        .request()) {
                    assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                    assertThat(response.as(String.class), is("ID Token is invalid"));
                    assertNoLocalAuthenticationCookie(response, tenant);
                }
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteMergesUserInfoClaims(URI serverUri) {
        userInfoEndpointResponseBody = userInfoEndpointResponse(SUBJECT)
                .set("preferred_username", "userinfo-user")
                .set("email", "userinfo@example.org")
                .setStrings("groups", List.of("admin", "auditor"))
                .build()
                .toString();
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri);
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
                assertThat(USER_INFO_AUTHORIZATION.get(), is("Bearer access-token"));

                SetCookie localAuthenticationCookie = SetCookie.parse(response.headers()
                        .get(HeaderNames.SET_COOKIE)
                        .allValues()
                        .stream()
                        .filter(cookie -> cookie.startsWith(tenant.cookies().localAuthenticationCookieName() + "="))
                        .findFirst()
                        .orElseThrow());
                JsonObject storedUserInfo = OidcCookieStateHandler.create("default", tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value(),
                                                         OidcIdTokenDecryptor.create(tenant))
                        .orElseThrow()
                        .userInfo()
                        .orElseThrow();
                assertThat(storedUserInfo.stringValue("preferred_username").orElse(""), is("userinfo-user"));
                assertThat(storedUserInfo.value("email").isEmpty(), is(true));
                assertThat(storedUserInfo.value("groups").isPresent(), is(true));

                AuthenticationResponse authentication = OidcProvider.create(providerConfig(tenant))
                        .authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                                .targetUri(URI.create("https://rp.example/resource"))
                                .header(HeaderNames.COOKIE.defaultCase(),
                                        localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                                .build()));

                assertThat(authentication.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                Subject subject = authentication.user().orElseThrow();
                assertThat(subject.principal().id(), is(issuerSubjectPrincipalId()));
                assertThat(subject.principal().getName(), is("userinfo-user"));
                assertThat(subject.principal().abacAttributeRaw("email"), is(EMAIL));
                assertThat(subject.grants(Role.class).stream().map(Role::getName).toList(),
                           is(List.of("admin", "auditor")));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void tenantAdapterValidatesUserInfoBeforeAWebSessionIsIssued(URI serverUri) {
        AtomicInteger checks = new AtomicInteger();
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "userinfo-test";
            }

            @Override
            public String type() {
                return "userinfo-test";
            }

            @Override
            public void validateUserInfo(OidcTenantConfig tenant, JsonObject claims) {
                checks.incrementAndGet();
                if (!claims.booleanValue("vendor_verified").orElse(false)) {
                    throw new IllegalArgumentException("UserInfo is not verified by the provider");
                }
            }
        };
        OidcTenantConfig tenant = OidcTenantConfig.builder(tenantConfigWithUserInfo(serverUri))
                .adapter(adapter)
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            for (boolean verified : List.of(true, false)) {
                userInfoEndpointResponseBody = userInfoEndpointResponse(SUBJECT)
                        .set("vendor_verified", verified).build().toString();
                SetCookie stateCookie = authenticationRequestCookie(callbackUri(rpServer), tenant);
                try (HttpClientResponse response = WebClient.builder()
                        .baseUri(rpBaseUri(rpServer))
                        .build()
                        .get("/oidc/callback")
                        .followRedirects(false)
                        .queryParam("code", "authorization-code")
                        .queryParam("state", STATE)
                        .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                        .request()) {
                    assertThat(response.status(), is(verified ? Status.SEE_OTHER_303 : Status.BAD_GATEWAY_502));
                    if (!verified) {
                        assertNoLocalAuthenticationCookie(response, tenant);
                    }
                }
            }
            assertThat(checks.get(), is(2));
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteMergesEncryptedUserInfoClaims(URI serverUri) {
        userInfoEndpointContentType = "application/jwt";
        userInfoEndpointResponseBody = encryptedUserInfo(SUBJECT,
                                                         EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                                         EncryptedJwt.SupportedEncryption.A128CBC_HS256,
                                                         encryptKeys,
                                                         "encrypt-rsa");
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           userInfo -> userInfo.jwt(jwt -> jwt
                                                                   .encryptionAlgorithm("RSA-OAEP-256")
                                                                   .decryptionJwk(ResourceConfig.builder()
                                                                           .resourcePath("oidc-next-encrypt-jwk.json")
                                                                           .buildPrototype())));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));

                SetCookie localAuthenticationCookie = localAuthenticationCookie(response, tenant);
                JsonObject storedUserInfo = OidcCookieStateHandler.create("default", tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value(),
                                                         OidcIdTokenDecryptor.create(tenant))
                        .orElseThrow()
                        .userInfo()
                        .orElseThrow();
                assertThat(storedUserInfo.stringValue("preferred_username").orElse(""), is("userinfo-user"));
                assertThat(storedUserInfo.value("groups").isPresent(), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteMergesSignedAndEncryptedUserInfoClaims(URI serverUri) {
        userInfoEndpointContentType = "application/jwt";
        userInfoEndpointResponseBody = encryptedSignedUserInfo(SUBJECT,
                                                               EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                                               EncryptedJwt.SupportedEncryption.A256GCM);
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           userInfo -> userInfo.jwt(jwt -> jwt
                                                                   .signingAlgorithm("RS256")
                                                                   .encryptionAlgorithm("RSA-OAEP-256")
                                                                   .contentEncryptionAlgorithm("A256GCM")
                                                                   .decryptionJwk(ResourceConfig.builder()
                                                                           .resourcePath("oidc-next-encrypt-jwk.json")
                                                                           .buildPrototype())));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));

                SetCookie localAuthenticationCookie = localAuthenticationCookie(response, tenant);
                JsonObject storedUserInfo = OidcCookieStateHandler.create("default", tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value(),
                                                         OidcIdTokenDecryptor.create(tenant))
                        .orElseThrow()
                        .userInfo()
                        .orElseThrow();
                assertThat(storedUserInfo.stringValue("preferred_username").orElse(""), is("userinfo-user"));
                assertThat(storedUserInfo.value("groups").isPresent(), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteMergesSignedJwtUserInfoClaims(URI serverUri) {
        userInfoEndpointContentType = "application/jwt";
        userInfoEndpointResponseBody = signedUserInfo("RS384",
                                                      SUBJECT,
                                                      ISSUER.toString(),
                                                      CLIENT_ID,
                                                      jwt -> jwt.preferredUsername("userinfo-user")
                                                              .email("userinfo@example.org")
                                                              .addUserGroup("admin")
                                                              .addUserGroup("auditor"));
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           serverUri.resolve("single-jwks"),
                                                           userInfo -> userInfo.jwt(jwt -> jwt
                                                                   .signingAlgorithm("RS384")));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
                assertThat(USER_INFO_AUTHORIZATION.get(), is("Bearer access-token"));

                SetCookie localAuthenticationCookie = SetCookie.parse(response.headers()
                        .get(HeaderNames.SET_COOKIE)
                        .allValues()
                        .stream()
                        .filter(cookie -> cookie.startsWith(tenant.cookies().localAuthenticationCookieName() + "="))
                        .findFirst()
                        .orElseThrow());
                JsonObject storedUserInfo = OidcCookieStateHandler.create("default", tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value(),
                                                         OidcIdTokenDecryptor.create(tenant))
                        .orElseThrow()
                        .userInfo()
                        .orElseThrow();
                assertThat(storedUserInfo.stringValue("preferred_username").orElse(""), is("userinfo-user"));
                assertThat(storedUserInfo.value("email").isEmpty(), is(true));
                assertThat(storedUserInfo.value("groups").isPresent(), is(true));

                AuthenticationResponse authentication = OidcProvider.create(providerConfig(tenant))
                        .authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                                .targetUri(URI.create("https://rp.example/resource"))
                                .header(HeaderNames.COOKIE.defaultCase(),
                                        localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                                .build()));

                assertThat(authentication.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                Subject subject = authentication.user().orElseThrow();
                assertThat(subject.principal().id(), is(issuerSubjectPrincipalId()));
                assertThat(subject.principal().getName(), is("userinfo-user"));
                assertThat(subject.principal().abacAttributeRaw("email"), is(EMAIL));
                assertThat(subject.grants(Role.class).stream().map(Role::getName).toList(),
                           is(List.of("admin", "auditor")));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsInvalidEncryptedUserInfo(URI serverUri) throws Exception {
        userInfoEndpointContentType = "application/jwt";
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           userInfo -> userInfo.jwt(jwt -> jwt
                                                                   .encryptionAlgorithm("RSA-OAEP-256")
                                                                   .contentEncryptionAlgorithm("A256GCM")
                                                                   .decryptionJwk(ResourceConfig.builder()
                                                                           .resourcePath("oidc-next-encrypt-jwk.json")
                                                                           .buildPrototype())));
        String validEncrypted = encryptedUserInfo(SUBJECT,
                                                  EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                                  EncryptedJwt.SupportedEncryption.A256GCM,
                                                  encryptKeys,
                                                  "encrypt-rsa");
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            for (String invalidResponse : List.of(
                    OidcTestJwe.encrypt(userInfoEndpointResponse(SUBJECT).build().toString(),
                                        encryptKeys,
                                        false,
                                        JsonObject.builder().setStrings("crit", List.of("extension"))
                                                .set("extension", true).build()),
                    OidcTestJwe.encrypt(userInfoEndpointResponse(SUBJECT).build().toString(),
                                        encryptKeys,
                                        false,
                                        JsonObject.builder().setStrings("crit", List.of()).build()),
                    encryptedUserInfo(SUBJECT,
                                      EncryptedJwt.SupportedAlgorithm.RSA_OAEP,
                                      EncryptedJwt.SupportedEncryption.A256GCM,
                                      encryptKeys,
                                      "encrypt-rsa"),
                    encryptedUserInfo(SUBJECT,
                                      EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                      EncryptedJwt.SupportedEncryption.A128CBC_HS256,
                                      encryptKeys,
                                      "encrypt-rsa"),
                    encryptedSignedUserInfo(SUBJECT,
                                            EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                            EncryptedJwt.SupportedEncryption.A256GCM),
                    tamperedAuthenticationTag(validEncrypted),
                    encryptedUserInfo("other-subject",
                                      EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                      EncryptedJwt.SupportedEncryption.A256GCM,
                                      encryptKeys,
                                      "encrypt-rsa"),
                    encryptedUserInfo(SUBJECT,
                                      EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                      EncryptedJwt.SupportedEncryption.A256GCM,
                                      signKeys,
                                      "sign-rsa"),
                    encryptedPayload("not-json".getBytes(StandardCharsets.UTF_8),
                                     EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                     EncryptedJwt.SupportedEncryption.A256GCM,
                                     encryptKeys,
                                     "encrypt-rsa"),
                    encryptedPayload(new byte[] {(byte) 0xC3, (byte) 0x28},
                                     EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                     EncryptedJwt.SupportedEncryption.A256GCM,
                                     encryptKeys,
                                     "encrypt-rsa"))) {
                userInfoEndpointResponseBody = invalidResponse;
                URI callbackUri = callbackUri(rpServer);
                SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

                try (HttpClientResponse response = WebClient.builder()
                        .baseUri(rpBaseUri(rpServer))
                        .build()
                        .get("/oidc/callback")
                        .queryParam("code", "authorization-code")
                        .queryParam("state", STATE)
                        .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                        .request()) {
                    assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                    assertThat(response.as(String.class), is("UserInfo response is invalid"));
                    assertNoLocalAuthenticationCookie(response, tenant);
                }
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsUserInfoResponseModeMismatch(URI serverUri) {
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           userInfo -> userInfo.jwt(jwt -> jwt
                                                                   .signingAlgorithm("RS256")));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("UserInfo response is invalid"));
                assertNoLocalAuthenticationCookie(response, tenant);
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsUnexpectedJwtUserInfo(URI serverUri) {
        userInfoEndpointContentType = "application/jwt";
        userInfoEndpointResponseBody = signedUserInfo(SUBJECT, ISSUER.toString(), CLIENT_ID, _ -> { });
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri);
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("UserInfo response is invalid"));
                assertNoLocalAuthenticationCookie(response, tenant);
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsInvalidNestedUserInfo(URI serverUri) {
        userInfoEndpointContentType = "application/jwt";
        String signed = signedUserInfo(SUBJECT, ISSUER.toString(), CLIENT_ID, _ -> { });
        userInfoEndpointResponseBody = encryptedSignedPayload(tamperedSignature(signed),
                                                              EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                                              EncryptedJwt.SupportedEncryption.A256GCM);
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           userInfo -> userInfo.jwt(jwt -> jwt
                                                                   .signingAlgorithm("RS256")
                                                                   .encryptionAlgorithm("RSA-OAEP-256")
                                                                   .contentEncryptionAlgorithm("A256GCM")
                                                                   .decryptionJwk(ResourceConfig.builder()
                                                                           .resourcePath("oidc-next-encrypt-jwk.json")
                                                                           .buildPrototype())));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("UserInfo response is invalid"));
                assertNoLocalAuthenticationCookie(response, tenant);
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteStoresExplicitUserInfoAttributes(URI serverUri) {
        userInfoEndpointResponseBody = userInfoEndpointResponse(SUBJECT)
                .set("preferred_username", "userinfo-user")
                .set("email", "userinfo@example.org")
                .set("department", "finance")
                .build()
                .toString();
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           userInfo -> userInfo
                                                                   .attributeClaimPaths(List.of("email",
                                                                                                "department")));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));

                SetCookie localAuthenticationCookie = SetCookie.parse(response.headers()
                        .get(HeaderNames.SET_COOKIE)
                        .allValues()
                        .stream()
                        .filter(cookie -> cookie.startsWith(tenant.cookies().localAuthenticationCookieName() + "="))
                        .findFirst()
                        .orElseThrow());
                JsonObject storedUserInfo = OidcCookieStateHandler.create("default", tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value(),
                                                         OidcIdTokenDecryptor.create(tenant))
                        .orElseThrow()
                        .userInfo()
                        .orElseThrow();
                assertThat(storedUserInfo.stringValue("email").orElse(""), is("userinfo@example.org"));
                assertThat(storedUserInfo.stringValue("department").orElse(""), is("finance"));

                AuthenticationResponse authentication = OidcProvider.create(providerConfig(tenant))
                        .authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                                .targetUri(URI.create("https://rp.example/resource"))
                                .header(HeaderNames.COOKIE.defaultCase(),
                                        localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                                .build()));

                assertThat(authentication.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                Subject subject = authentication.user().orElseThrow();
                assertThat(subject.principal().getName(), is("userinfo-user"));
                assertThat(subject.principal().abacAttributeRaw("email"), is("userinfo@example.org"));
                assertThat(subject.principal().abacAttributeRaw("department"), is("finance"));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteDiscardsUserInfoWhenStoragePolicyNone(URI serverUri) {
        userInfoEndpointResponseBody = userInfoEndpointResponse(SUBJECT)
                .set("preferred_username", "userinfo-user")
                .set("email", "userinfo@example.org")
                .setStrings("groups", List.of("admin"))
                .build()
                .toString();
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           userInfo -> userInfo
                                                                   .storagePolicy(OidcUserInfoStoragePolicy.NONE));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .followRedirects(false)
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
                assertThat(USER_INFO_AUTHORIZATION.get(), is("Bearer access-token"));

                SetCookie localAuthenticationCookie = SetCookie.parse(response.headers()
                        .get(HeaderNames.SET_COOKIE)
                        .allValues()
                        .stream()
                        .filter(cookie -> cookie.startsWith(tenant.cookies().localAuthenticationCookieName() + "="))
                        .findFirst()
                        .orElseThrow());
                assertThat(OidcCookieStateHandler.create("default", tenant)
                                   .decodeLocalAuthenticationResult(localAuthenticationCookie.value(),
                                                                    OidcIdTokenDecryptor.create(tenant))
                                   .orElseThrow()
                                   .userInfo()
                                   .isEmpty(),
                           is(true));

                AuthenticationResponse authentication = OidcProvider.create(providerConfig(tenant))
                        .authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                                .targetUri(URI.create("https://rp.example/resource"))
                                .header(HeaderNames.COOKIE.defaultCase(),
                                        localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                                .build()));

                assertThat(authentication.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                Subject subject = authentication.user().orElseThrow();
                assertThat(subject.principal().getName(), is(USERNAME));
                assertThat(subject.principal().abacAttributeRaw("email"), is(EMAIL));
                assertThat(subject.grants(Role.class).isEmpty(), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsUserInfoSubjectMismatch(URI serverUri) {
        userInfoEndpointResponseBody = userInfoEndpointResponse("other-subject").build().toString();
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri);
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("UserInfo response is invalid"));
                assertThat(USER_INFO_AUTHORIZATION.get(), is("Bearer access-token"));
                assertNoLocalAuthenticationCookie(response, tenant);
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsInvalidUserInfoSubjectValues(URI serverUri) {
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri);
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            for (String invalidResponse : List.of(JsonObject.builder().build().toString(),
                                                  userInfoEndpointResponse("").build().toString(),
                                                  JsonObject.builder().set("sub", true).build().toString())) {
                userInfoEndpointResponseBody = invalidResponse;
                URI callbackUri = callbackUri(rpServer);
                SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

                try (HttpClientResponse response = WebClient.builder()
                        .baseUri(rpBaseUri(rpServer))
                        .build()
                        .get("/oidc/callback")
                        .queryParam("code", "authorization-code")
                        .queryParam("state", STATE)
                        .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                        .request()) {
                    assertThat(invalidResponse, response.status(), is(Status.BAD_GATEWAY_502));
                    assertThat(invalidResponse, response.as(String.class), is("UserInfo response is invalid"));
                    assertNoLocalAuthenticationCookie(response, tenant);
                }
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsInvalidSignedJwtUserInfo(URI serverUri) {
        userInfoEndpointContentType = "application/jwt";
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           userInfo -> userInfo.jwt(jwt -> jwt
                                                                   .signingAlgorithm("RS256")));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            for (String invalidResponse : List.of(tamperedSignature(signedUserInfo(SUBJECT,
                                                                                   ISSUER.toString(),
                                                                                   CLIENT_ID,
                                                                                   _ -> { })),
                                                  unsignedUserInfo(),
                                                  signedUserInfo("other-subject",
                                                                 ISSUER.toString(),
                                                                 CLIENT_ID,
                                                                 _ -> { }),
                                                  signedUserInfo(SUBJECT,
                                                                 "https://other-issuer.example",
                                                                 CLIENT_ID,
                                                                 _ -> { }),
                                                  signedUserInfo(SUBJECT,
                                                                 ISSUER.toString(),
                                                                 "other-client",
                                                                 _ -> { }))) {
                userInfoEndpointResponseBody = invalidResponse;
                URI callbackUri = callbackUri(rpServer);
                SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

                try (HttpClientResponse response = WebClient.builder()
                        .baseUri(rpBaseUri(rpServer))
                        .build()
                        .get("/oidc/callback")
                        .queryParam("code", "authorization-code")
                        .queryParam("state", STATE)
                        .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                        .request()) {
                    assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                    assertThat(response.as(String.class), is("UserInfo response is invalid"));
                    assertNoLocalAuthenticationCookie(response, tenant);
                }
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsUserInfoEndpointError(URI serverUri) {
        userInfoEndpointStatus = Status.UNAUTHORIZED_401;
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri);
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("UserInfo Endpoint request failed"));
                assertThat(USER_INFO_AUTHORIZATION.get(), is("Bearer access-token"));
                assertNoLocalAuthenticationCookie(response, tenant);
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsMalformedUserInfoResponse(URI serverUri) {
        userInfoEndpointResponseBody = "{invalid-json";
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri);
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("UserInfo Endpoint request failed"));
                assertNoLocalAuthenticationCookie(response, tenant);
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsUserInfoResponseWithoutJsonContentType(URI serverUri) {
        userInfoEndpointContentType = null;
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri);
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenant);

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("UserInfo Endpoint request failed"));
                assertNoLocalAuthenticationCookie(response, tenant);
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteIsNotRegisteredWhenLogoutIsNotConfigured(WebClient client) {
        try (HttpClientResponse response = client.post("/oidc/logout")
                .request()) {
            assertThat(response.status(), is(Status.NOT_FOUND_404));
        }
    }

    @Test
    void logoutEndpointRouteIsNotRegisteredWhenLogoutIsDisabled() {
        WebServer rpServer = oidcFeatureServer(providerConfig(tenantConfigWithLogout(logout -> logout.enabled(false))));
        try {
            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .request()) {
                assertThat(response.status(), is(Status.NOT_FOUND_404));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteRemovesLocalAuthenticationCookies() {
        OidcTenantConfig tenant = tenantConfigWithLogout();
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");
            SetCookie authenticationRequestCookie = authenticationRequestCookie(CONFIGURED_REDIRECTION_ENDPOINT_URI, tenant);
            OidcCookieStateHandler cookieStateHandler = OidcCookieStateHandler.create("default", tenant);
            OidcCookieStateHandler.BrowserSessionGeneration previousGeneration =
                    cookieStateHandler.createBrowserSessionGeneration();

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE,
                            cookieHeader(localAuthenticationCookie, authenticationRequestCookie) + "; "
                                    + previousGeneration.cookie().name() + "=" + previousGeneration.cookie().value())
                    .request()) {
                assertThat(response.status(), is(Status.NO_CONTENT_204));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.size(), is(18));
                assertRemovalCookie(cookies, tenant.cookies().localAuthenticationCookieName());
                assertRemovalCookie(cookies, tenant.cookies().authenticationRequestCookieName());
                SetCookie generationCookie = assertBrowserSessionGenerationCookie(cookies, tenant, "default");
                assertThat(cookieStateHandler.readBrowserSessionGeneration(generationCookie.value())
                                   .orElseThrow()
                                   .equals(previousGeneration.value()),
                           is(false));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteRejectsMissingSameOriginSignal() {
        OidcTenantConfig tenant = tenantConfigWithLogout();
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.FORBIDDEN_403));
                assertThat(response.headers().contains(HeaderNames.SET_COOKIE), is(false));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteDoesNotRemoveCookiesOverGet() {
        OidcTenantConfig tenant = tenantConfigWithLogout();
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/logout")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.NOT_FOUND_404));
                assertThat(response.headers().contains(HeaderNames.SET_COOKIE), is(false));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteUsesLocalAuthenticationCookieTenant() {
        OidcTenantConfig tenantA = tenantConfigWithLogout("state-a", "auth", "shared-cookie-password");
        OidcTenantConfig tenantB = tenantConfigWithLogout("state-b", "auth", "shared-cookie-password");
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("tenant-a", tenantA)
                .putTenant("tenant-b", tenantB)
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(config);
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenantB, "tenant-b");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.NO_CONTENT_204));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.size(), is(18));
                assertRemovalCookie(cookies, "auth");
                assertRemovalCookie(cookies, "state-b");
                assertBrowserSessionGenerationCookie(cookies, tenantB, "tenant-b");
                assertThat(cookies.stream().noneMatch(cookie -> cookie.startsWith("state-a=")), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteClearsAllPathTenantsWhenLocalAuthenticationCookieTenantIsAmbiguous() {
        OidcTenantConfig tenantA = tenantConfigWithLogout("state-a", "auth-a", "tenant-a-cookie-password");
        OidcTenantConfig tenantB = tenantConfigWithLogout("state-b", "auth-b", "tenant-b-cookie-password");
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("tenant-a", tenantA)
                .putTenant("tenant-b", tenantB)
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(config);
        try {
            SetCookie localAuthenticationCookieA = localAuthenticationCookie(tenantA, "tenant-a");
            SetCookie localAuthenticationCookieB = localAuthenticationCookie(tenantB, "tenant-b");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE, cookieHeader(localAuthenticationCookieA, localAuthenticationCookieB))
                    .request()) {
                assertThat(response.status(), is(Status.NO_CONTENT_204));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.size(), is(36));
                assertRemovalCookie(cookies, "auth-a");
                assertRemovalCookie(cookies, "state-a");
                assertRemovalCookie(cookies, "auth-b");
                assertRemovalCookie(cookies, "state-b");
                assertBrowserSessionGenerationCookie(cookies, tenantA, "tenant-a");
                assertBrowserSessionGenerationCookie(cookies, tenantB, "tenant-b");
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteClearsAllLogoutTenantCookiesWhenTenantIsUnresolved() {
        OidcTenantConfig tenantA = tenantConfigWithLogout("state-a", "auth-a", "tenant-a-cookie-password");
        OidcTenantConfig tenantB = tenantConfigWithLogout("state-b", "auth-b", "tenant-b-cookie-password");
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("tenant-a", tenantA)
                .putTenant("tenant-b", tenantB)
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(config);
        try {
            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .request()) {
                assertThat(response.status(), is(Status.NO_CONTENT_204));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.size(), is(36));
                assertRemovalCookie(cookies, "auth-a");
                assertRemovalCookie(cookies, "state-a");
                assertRemovalCookie(cookies, "auth-b");
                assertRemovalCookie(cookies, "state-b");
                assertBrowserSessionGenerationCookie(cookies, tenantA, "tenant-a");
                assertBrowserSessionGenerationCookie(cookies, tenantB, "tenant-b");
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteFallbackUsesOnlyRequestedPathTenants() {
        OidcTenantConfig tenantA = tenantConfigWithLogout("state-a",
                                                          "auth-a",
                                                          "tenant-a-cookie-password",
                                                          logout -> logout.localEndpointUri(URI.create("/oidc/logout-a")));
        OidcTenantConfig tenantB = tenantConfigWithLogout("state-b",
                                                          "auth-b",
                                                          "tenant-b-cookie-password",
                                                          logout -> logout.localEndpointUri(URI.create("/oidc/logout-b")));
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("tenant-a", tenantA)
                .putTenant("tenant-b", tenantB)
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(config);
        try {
            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout-a")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .request()) {
                assertThat(response.status(), is(Status.NO_CONTENT_204));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.size(), is(18));
                assertRemovalCookie(cookies, "auth-a");
                assertRemovalCookie(cookies, "state-a");
                assertBrowserSessionGenerationCookie(cookies, tenantA, "tenant-a");
                assertThat(cookies.stream().noneMatch(cookie -> cookie.startsWith("auth-b=")), is(true));
                assertThat(cookies.stream().noneMatch(cookie -> cookie.startsWith("state-b=")), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteUsesExactPathMatching() {
        OidcTenantConfig tenant = tenantConfigWithLogout(logout -> logout.localEndpointUri(URI.create("/oidc/*")));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/anything")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .request()) {
                assertThat(response.status(), is(Status.NOT_FOUND_404));
                assertThat(response.headers().contains(HeaderNames.SET_COOKIE), is(false));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteRedirectsToEndSessionEndpoint() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(endSession -> endSession
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            String rawIdToken = signedIdToken(NONCE);
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default", rawIdToken);
            String localAuthenticationHeader = localAuthenticationCookie.name()
                    + "="
                    + localAuthenticationCookie.value();

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .followRedirects(false)
                    .queryParam("state", "logout-state")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE, localAuthenticationHeader)
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));

                URI location = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                assertThat(location.getScheme(), is(END_SESSION_ENDPOINT_URI.getScheme()));
                assertThat(location.getAuthority(), is(END_SESSION_ENDPOINT_URI.getAuthority()));
                assertThat(location.getPath(), is(END_SESSION_ENDPOINT_URI.getPath()));
                UriQuery query = UriQuery.create(location);
                assertThat(query.first("id_token_hint").orElse(""), is(rawIdToken));
                assertThat(query.first("post_logout_redirect_uri").orElse(""), is(POST_LOGOUT_REDIRECT_URI.toString()));
                assertThat(query.first("state").orElse(""), is("logout-state"));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.size(), is(18));
                assertRemovalCookie(cookies, tenant.cookies().localAuthenticationCookieName());
                assertRemovalCookie(cookies, tenant.cookies().authenticationRequestCookieName());
                assertBrowserSessionGenerationCookie(cookies, tenant, "default");
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void tenantAdapterCanCustomizeEndSessionQueryButNotItsValidatedRedirect() {
        AtomicBoolean invalidRedirect = new AtomicBoolean();
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "end-session-test";
            }

            @Override
            public String type() {
                return "end-session-test";
            }

            @Override
            public Parameters endSessionRequest(OidcTenantConfig tenant, Parameters parameters) {
                Map<String, List<String>> values = parameters.toMap();
                values.put("logout_hint", List.of("provider-session"));
                values.put("client_id", List.of(CLIENT_ID));
                if (invalidRedirect.get()) {
                    values.put("post_logout_redirect_uri", List.of("https://attacker.example/logout"));
                }
                return Parameters.create("adapted-end-session", values);
            }
        };
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(
                endSession -> endSession.postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI),
                builder -> builder.adapter(adapter));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie cookie = localAuthenticationCookie(tenant, "default", signedIdToken(NONCE));
            for (boolean invalid : List.of(false, true)) {
                invalidRedirect.set(invalid);
                try (HttpClientResponse response = WebClient.builder()
                        .baseUri(rpBaseUri(rpServer))
                        .build()
                        .post("/oidc/logout")
                        .followRedirects(false)
                        .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                        .header(HeaderNames.COOKIE, cookie.name() + "=" + cookie.value())
                        .request()) {
                    assertThat(response.status(), is(invalid ? Status.BAD_GATEWAY_502 : Status.SEE_OTHER_303));
                    if (invalid) {
                        assertThat(response.headers().first(HeaderNames.LOCATION).isEmpty(), is(true));
                    } else {
                        UriQuery query = UriQuery.create(URI.create(response.headers()
                                                                            .first(HeaderNames.LOCATION).orElseThrow()));
                        assertThat(query.first("logout_hint").orElse(""), is("provider-session"));
                        assertThat(query.first("client_id").orElse(""), is(CLIENT_ID));
                        assertThat(query.first("post_logout_redirect_uri").orElse(""),
                                   is(POST_LOGOUT_REDIRECT_URI.toString()));
                    }
                    assertRemovalCookie(response.headers().get(HeaderNames.SET_COOKIE).allValues(),
                                        tenant.cookies().localAuthenticationCookieName());
                }
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteUsesEncryptedIdTokenHintWithClientId() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(
                  endSession -> endSession.postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI),
                  builder -> builder.idToken(idToken -> idToken
                          .decryptionJwk(ResourceConfig.builder()
                                  .resourcePath("oidc-next-encrypt-jwk.json")
                                  .buildPrototype())));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            String signedIdToken = signedIdToken(NONCE);
            String encryptedIdToken = encryptedIdToken(signedIdToken);
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                            "default",
                                                                            encryptedIdToken,
                                                                            signedIdToken,
                                                                            true);
            String localAuthenticationHeader = localAuthenticationCookie.name()
                    + "="
                    + localAuthenticationCookie.value();

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .followRedirects(false)
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE, localAuthenticationHeader)
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));

                URI location = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                UriQuery query = UriQuery.create(location);
                assertThat(query.first("id_token_hint").orElse(""), is(encryptedIdToken));
                assertThat(query.first("client_id").orElse(""), is(CLIENT_ID));
                assertThat(query.first("post_logout_redirect_uri").orElse(""), is(POST_LOGOUT_REDIRECT_URI.toString()));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteRejectsUnallowedPostLogoutRedirectUri() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(endSession -> endSession
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .queryParam("post_logout_redirect_uri", "https://attacker.example/logged-out")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                    assertThat(response.as(String.class), is("Logout request is invalid"));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.size(), is(18));
                assertRemovalCookie(cookies, tenant.cookies().localAuthenticationCookieName());
                assertRemovalCookie(cookies, tenant.cookies().authenticationRequestCookieName());
                assertBrowserSessionGenerationCookie(cookies, tenant, "default");
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteRejectsPostLogoutRedirectUriHostCaseMismatch() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(endSession -> endSession
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .queryParam("post_logout_redirect_uri", "https://RP.example/logged-out")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(response.as(String.class), is("Logout request is invalid"));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteAcceptsAllowedPostLogoutRedirectUriFromRequest() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(endSession -> endSession
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI)
                .addAllowedPostLogoutRedirectUri(OTHER_POST_LOGOUT_REDIRECT_URI));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .followRedirects(false)
                    .queryParam("post_logout_redirect_uri", OTHER_POST_LOGOUT_REDIRECT_URI.toString())
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));

                URI location = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                UriQuery query = UriQuery.create(location);
                assertThat(query.first("post_logout_redirect_uri").orElse(""),
                           is(OTHER_POST_LOGOUT_REDIRECT_URI.toString()));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteRejectsAllowedPostLogoutRedirectUriPercentEncodingCaseMismatch() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(endSession -> endSession
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI)
                .addAllowedPostLogoutRedirectUri(URI.create("https://rp.example/%7elogged-out")));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .queryParam("post_logout_redirect_uri", "https://rp.example/%7Elogged-out")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(response.as(String.class), is("Logout request is invalid"));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteRejectsMissingIdTokenHintWhenRequired() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(_ -> { });
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .request()) {
                assertThat(response.status(), is(Status.FORBIDDEN_403));
                assertThat(response.as(String.class), is("id_token_hint is required for RP-Initiated Logout"));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.size(), is(18));
                assertRemovalCookie(cookies, tenant.cookies().localAuthenticationCookieName());
                assertRemovalCookie(cookies, tenant.cookies().authenticationRequestCookieName());
                assertBrowserSessionGenerationCookie(cookies, tenant, "default");
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteCanOmitIdTokenHintWhenConfigured() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(endSession -> endSession
                .idTokenHintRequired(false)
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .followRedirects(false)
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));

                URI location = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                UriQuery query = UriQuery.create(location);
                assertThat(query.first("id_token_hint").isEmpty(), is(true));
                assertThat(query.first("client_id").orElse(""), is(CLIENT_ID));
                assertThat(query.first("post_logout_redirect_uri").orElse(""), is(POST_LOGOUT_REDIRECT_URI.toString()));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void featureStartupDefersDiscoveredMetadataUntilLogoutRequest() {
        AtomicInteger metadataRequestCount = new AtomicInteger();
        WebServer opServer = wellKnownEndSessionServer(metadataRequestCount);
        try {
            URI issuer = issuerUri(opServer);
            OidcTenantConfig tenant = tenantConfigWithDiscoveredEndSessionLogout(issuer, endSession -> endSession
                    .idTokenHintRequired(false)
                    .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI));
            WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
            try {
                assertThat(metadataRequestCount.get(), is(0));

                try (HttpClientResponse response = WebClient.builder()
                        .baseUri(rpBaseUri(rpServer))
                        .build()
                        .post("/oidc/logout")
                        .followRedirects(false)
                        .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                        .request()) {
                    assertThat(response.status(), is(Status.SEE_OTHER_303));

                    URI location = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                    assertThat(location.getScheme(), is(issuer.getScheme()));
                    assertThat(location.getAuthority(), is(issuer.getAuthority()));
                    assertThat(location.getPath(), is("/logout"));
                    UriQuery query = UriQuery.create(location);
                    assertThat(query.first("client_id").orElse(""), is(CLIENT_ID));
                    assertThat(query.first("post_logout_redirect_uri").orElse(""),
                               is(POST_LOGOUT_REDIRECT_URI.toString()));
                }
                assertThat(metadataRequestCount.get(), is(1));
            } finally {
                rpServer.stop();
            }
        } finally {
            opServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteAcceptsConfiguredPostLogoutRedirectUriFromRequest() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(endSession -> endSession
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .followRedirects(false)
                    .queryParam("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI.toString())
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));

                URI location = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                UriQuery query = UriQuery.create(location);
                assertThat(query.first("post_logout_redirect_uri").orElse(""),
                           is(POST_LOGOUT_REDIRECT_URI.toString()));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteRejectsInvalidPostLogoutRedirectUri() {
        OidcTenantConfig tenant = tenantConfigWithEndSessionLogout(endSession -> endSession
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI));
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant, "default");
            String localAuthenticationHeader = localAuthenticationCookie.name()
                    + "="
                    + localAuthenticationCookie.value();

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .queryParam("post_logout_redirect_uri", "https://rp.example/%zz")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE, localAuthenticationHeader)
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(response.as(String.class), is("Logout request is invalid"));
            }

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .queryParam("post_logout_redirect_uri", "")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE, localAuthenticationHeader)
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(response.as(String.class), is("Logout request is invalid"));
            }

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post()
                    .uri(URI.create("/oidc/logout?post_logout_redirect_uri=https%3A%2F%2Frp.example%2Flogged-out"
                                            + "&post_logout_redirect_uri=https%3A%2F%2Frp.example%2Fother-logged-out"))
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE, localAuthenticationHeader)
                    .request()) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
                assertThat(response.as(String.class), is("Logout request is invalid"));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteUsesLocalAuthenticationTenantForEndSessionRedirect() {
        URI tenantAEndSessionEndpoint = URI.create("https://issuer.example/logout-a");
        URI tenantBEndSessionEndpoint = URI.create("https://issuer.example/logout-b");
        OidcTenantConfig tenantA = tenantConfigWithEndSessionLogout("state-a",
                                                                    "auth",
                                                                    "shared-cookie-password",
                                                                    tenantAEndSessionEndpoint,
                                                                    _ -> { });
        OidcTenantConfig tenantB = tenantConfigWithEndSessionLogout("state-b",
                                                                    "auth",
                                                                    "shared-cookie-password",
                                                                    tenantBEndSessionEndpoint,
                                                                    _ -> { });
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("tenant-a", tenantA)
                .putTenant("tenant-b", tenantB)
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(config);
        try {
            SetCookie localAuthenticationCookie = localAuthenticationCookie(tenantB, "tenant-b");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .followRedirects(false)
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE,
                            localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));

                URI location = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                assertThat(location.getPath(), is(tenantBEndSessionEndpoint.getPath()));
                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertRemovalCookie(cookies, "auth");
                assertRemovalCookie(cookies, "state-b");
                assertBrowserSessionGenerationCookie(cookies, tenantB, "tenant-b");
                assertThat(cookies.stream().noneMatch(cookie -> cookie.startsWith("state-a=")), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteDoesNotRedirectWhenEndSessionTenantIsAmbiguous() {
        OidcTenantConfig tenantA = tenantConfigWithEndSessionLogout("state-a",
                                                                    "auth-a",
                                                                    "tenant-a-cookie-password",
                                                                    URI.create("https://issuer.example/logout-a"),
                                                                    _ -> { });
        OidcTenantConfig tenantB = tenantConfigWithEndSessionLogout("state-b",
                                                                    "auth-b",
                                                                    "tenant-b-cookie-password",
                                                                    URI.create("https://issuer.example/logout-b"),
                                                                    _ -> { });
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("tenant-a", tenantA)
                .putTenant("tenant-b", tenantB)
                .buildPrototype();
        WebServer rpServer = oidcFeatureServer(config);
        try {
            SetCookie localAuthenticationCookieA = localAuthenticationCookie(tenantA, "tenant-a");
            SetCookie localAuthenticationCookieB = localAuthenticationCookie(tenantB, "tenant-b");

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .followRedirects(false)
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE, cookieHeader(localAuthenticationCookieA, localAuthenticationCookieB))
                    .request()) {
                assertThat(response.status(), is(Status.NO_CONTENT_204));
                assertThat(response.headers().contains(HeaderNames.LOCATION), is(false));
            }
        } finally {
            rpServer.stop();
        }
    }

    private static OidcProviderConfig providerConfig() {
        return OidcProviderConfig.builder()
                .putTenant("default", tenantConfig())
                .buildPrototype();
    }

    private static OidcProviderConfig collidingIssuerProviderConfig(URI serverUri) {
        COLLIDING_ISSUER_METADATA.set(JsonObject.builder()
                                              .set("issuer", ISSUER.toString())
                                              .set("authorization_endpoint", AUTHORIZATION_ENDPOINT_URI.toString())
                                              .set("token_endpoint", serverUri.resolve("attacker-token").toString())
                                              .set("jwks_uri", serverUri.resolve("jwks").toString())
                                              .setStrings("response_types_supported", List.of("code"))
                                              .setStrings("grant_types_supported", List.of("authorization_code"))
                                              .setStrings("code_challenge_methods_supported", List.of("S256"))
                                              .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                                              .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                                              .set("authorization_response_iss_parameter_supported", true)
                                              .build().toString());
        OidcTenantConfig attacker = OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(endpoints -> endpoints.wellKnownUri(serverUri.resolve("issuer-collision-metadata"))
                        .tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .cookies(cookies -> cookies.protection(protection -> protection.password(COOKIE_PASSWORD)))
                .buildPrototype();
        return OidcProviderConfig.builder()
                .putTenant("honest", tenantConfig(serverUri))
                .putTenant("attacker", attacker)
                .buildPrototype();
    }

    private static OidcProviderConfig providerConfig(OidcTenantConfig tenant) {
        return OidcProviderConfig.builder()
                .putTenant("default", tenant)
                .buildPrototype();
    }

    private static OidcProviderConfig providerConfig(URI openIdProviderUri) {
        return OidcProviderConfig.builder()
                .putTenant("default", tenantConfig(openIdProviderUri))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfig() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .jwksUri(JWKS_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .cookies(it -> it.protection(protection -> protection.password(COOKIE_PASSWORD)))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfigWithLogout() {
        return tenantConfigWithLogout(_ -> { });
    }

    private static OidcTenantConfig tenantConfigWithLogout(Consumer<OidcLogoutConfig.Builder> logout) {
        return tenantConfigWithLogout("__Host-helidon-oidc-state",
                                      "__Host-helidon-oidc-auth",
                                      COOKIE_PASSWORD,
                                      logout);
    }

    private static OidcTenantConfig tenantConfigWithEndSessionLogout(
            Consumer<OidcEndSessionConfig.Builder> endSession) {
        return tenantConfigWithEndSessionLogout(endSession, _ -> { });
    }

    private static OidcTenantConfig tenantConfigWithEndSessionLogout(
            Consumer<OidcEndSessionConfig.Builder> endSession,
            Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        return tenantConfigWithEndSessionLogout("__Host-helidon-oidc-state",
                                                "__Host-helidon-oidc-auth",
                                                COOKIE_PASSWORD,
                                                END_SESSION_ENDPOINT_URI,
                                                endSession,
                                                tenantCustomizer);
    }

    private static OidcTenantConfig tenantConfigWithEndSessionLogout(String authenticationRequestCookieName,
                                                                    String localAuthenticationCookieName,
                                                                    String cookiePassword,
                                                                    URI endSessionEndpointUri,
                                                                    Consumer<OidcEndSessionConfig.Builder> endSession) {
        return tenantConfigWithEndSessionLogout(authenticationRequestCookieName,
                                               localAuthenticationCookieName,
                                               cookiePassword,
                                               endSessionEndpointUri,
                                               endSession,
                                               _ -> { });
    }

    private static OidcTenantConfig tenantConfigWithEndSessionLogout(String authenticationRequestCookieName,
                                                                    String localAuthenticationCookieName,
                                                                    String cookiePassword,
                                                                    URI endSessionEndpointUri,
                                                                    Consumer<OidcEndSessionConfig.Builder> endSession,
                                                                    Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig.Builder builder = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .jwksUri(JWKS_URI)
                        .endSessionEndpointUri(endSessionEndpointUri))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .logout(logout -> logout.endSession(endSession))
                .cookies(it -> it.authenticationRequestCookieName(authenticationRequestCookieName)
                        .localAuthenticationCookieName(localAuthenticationCookieName)
                        .protection(protection -> protection.password(cookiePassword)));
        tenantCustomizer.accept(builder);
        return builder.buildPrototype();
    }

    private static OidcTenantConfig tenantConfigWithDiscoveredEndSessionLogout(
            URI issuer,
            Consumer<OidcEndSessionConfig.Builder> endSession) {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId(CLIENT_ID)
                .endpoints(it -> it.tlsRequired(false))
                .logout(logout -> logout.endSession(endSession))
                .cookies(it -> it.protection(protection -> protection.password(COOKIE_PASSWORD)))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfigWithLogout(String authenticationRequestCookieName,
                                                          String localAuthenticationCookieName,
                                                          String cookiePassword) {
        return tenantConfigWithLogout(authenticationRequestCookieName,
                                      localAuthenticationCookieName,
                                      cookiePassword,
                                      _ -> { });
    }

    private static OidcTenantConfig tenantConfigWithLogout(String authenticationRequestCookieName,
                                                          String localAuthenticationCookieName,
                                                          String cookiePassword,
                                                          Consumer<OidcLogoutConfig.Builder> logout) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .jwksUri(JWKS_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .logout(logout)
                .cookies(it -> it.authenticationRequestCookieName(authenticationRequestCookieName)
                        .localAuthenticationCookieName(localAuthenticationCookieName)
                        .protection(protection -> protection.password(cookiePassword)))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfig(URI openIdProviderUri) {
        return tenantConfig(openIdProviderUri, _ -> { });
    }

    private static OidcTenantConfig tenantConfig(URI openIdProviderUri,
                                                Consumer<OidcAuthorizationCodeConfig.Builder> authorizationCode) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(openIdProviderUri.resolve("token"))
                        .jwksUri(openIdProviderUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> {
                    it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                            .scopes(List.of("openid", "profile"));
                    authorizationCode.accept(it);
                })
                .cookies(it -> it.protection(protection -> protection.password(COOKIE_PASSWORD)))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfigWithUserInfo(URI openIdProviderUri) {
        return tenantConfigWithUserInfo(openIdProviderUri, _ -> { });
    }

    private static OidcTenantConfig tenantConfigWithUserInfo(URI openIdProviderUri,
                                                            Consumer<OidcUserInfoConfig.Builder> userInfo) {
        return tenantConfigWithUserInfo(openIdProviderUri, openIdProviderUri.resolve("jwks"), userInfo);
    }

    private static OidcTenantConfig tenantConfigWithUserInfo(URI openIdProviderUri,
                                                             URI verificationJwksUri,
                                                             Consumer<OidcUserInfoConfig.Builder> userInfo) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(openIdProviderUri.resolve("token"))
                        .userInfoEndpointUri(openIdProviderUri.resolve("userinfo"))
                        .jwksUri(verificationJwksUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .userInfo(userInfo)
                .cookies(it -> it.protection(protection -> protection.password(COOKIE_PASSWORD)))
                .buildPrototype();
    }

    private static String issuerSubjectPrincipalId() {
        return "oidc-sub:" + base64Url(ISSUER.toString()) + "." + base64Url(SUBJECT);
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static void tokenEndpointResponse(ServerResponse response) {
        response.header(HeaderValues.CONTENT_TYPE_JSON)
                .header(HeaderNames.CACHE_CONTROL, "no-store")
                .header(HeaderNames.PRAGMA, "no-cache")
                .send(tokenEndpointResponseBody);
    }

    private static JsonObject tokenEndpointResponse(String idToken) {
        return JsonObject.builder()
                .set("access_token", "access-token")
                .set("token_type", "Bearer")
                .set("id_token", idToken)
                .set("expires_in", 600)
                .build();
    }

    private static JsonObject.Builder userInfoEndpointResponse(String subject) {
        return JsonObject.builder()
                .set("sub", subject);
    }

    private static void assertNoLocalAuthenticationCookie(HttpClientResponse response, OidcTenantConfig tenant) {
        assertThat(response.headers()
                           .get(HeaderNames.SET_COOKIE)
                           .allValues()
                           .stream()
                           .noneMatch(cookie -> cookie.startsWith(tenant.cookies().localAuthenticationCookieName()
                                                                           + "=")),
                   is(true));
    }

    private static WebServer oidcFeatureServer(OidcProviderConfig config) {
        HttpRouting.Builder routing = HttpRouting.builder();
        OidcFeature.create(config).setup(routing);
        return WebServer.builder()
                .addRouting(routing)
                .port(0)
                .build()
                .start();
    }

    private static WebServer oidcFeatureServerWithRequestedUriDiscovery(OidcProviderConfig config) {
        HttpRouting.Builder routing = HttpRouting.builder();
        OidcFeature.create(config).setup(routing);
        return WebServer.builder()
                .addRouting(routing)
                .requestedUriDiscoveryContext(RequestedUriDiscoveryContext.builder()
                                                      .enabled(true)
                                                      .addDiscoveryType(RequestedUriDiscoveryContext
                                                                                .RequestedUriDiscoveryType
                                                                                .X_FORWARDED)
                                                      .trustedProxies(AllowList.builder()
                                                                              .allowAll(true)
                                                                              .build())
                                                      .build())
                .port(0)
                .build()
                .start();
    }

    private static WebServer wellKnownEndSessionServer(AtomicInteger metadataRequestCount) {
        AtomicReference<URI> issuer = new AtomicReference<>();
        HttpRouting.Builder routing = HttpRouting.builder();
        routing.get("/.well-known/openid-configuration", (_, response) -> {
            metadataRequestCount.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(JsonObject.builder()
                                  .set("issuer", issuer.get().toString())
                                  .set("end_session_endpoint", issuer.get().resolve("/logout").toString())
                                  .build()
                                  .toString());
        });
        WebServer server = WebServer.builder()
                .addRouting(routing)
                .port(0)
                .build()
                .start();
        issuer.set(issuerUri(server));
        return server;
    }

    private static void assertCallbackScopes(URI serverUri,
                                             Optional<String> adapterScope,
                                             Optional<String> responseScope,
                                             List<String> expectedScopes) {
        OidcTenantConfig.Builder tenantBuilder = OidcTenantConfig.builder(tenantConfig(serverUri,
                code -> code.redirectionEndpointUri(URI.create("/oidc/callback"))
                        .scopes(List.of("openid", "accounts.write"))));
        adapterScope.ifPresent(scope -> tenantBuilder.adapter(new OidcTenantAdapter() {
            @Override
            public String name() {
                return "scope-test-adapter";
            }

            @Override
            public String type() {
                return "scope-test-adapter";
            }

            @Override
            public OidcAuthorizationParameters authorizationRequest(OidcTenantConfig tenant,
                                                                    String tenantId,
                                                                    SecurityEnvironment environment,
                                                                    OidcAuthorizationParameters parameters) {
                OidcAuthorizationParameters.Builder values = OidcAuthorizationParameters.builder(parameters);
                values.putParameter("scope", List.of(JsonString.create(scope)));
                return values.buildPrototype();
            }
        }));
        OidcTenantConfig tenant = tenantBuilder.buildPrototype();
        try (OidcProvider provider = OidcProvider.create(providerConfig(tenant))) {
            WebClient client = WebClient.create();
            try {
                WebServer rp = WebServer.builder()
                        .host("127.0.0.1")
                        .port(0)
                        .addFeature(OidcFeature.create(provider))
                        .build()
                        .start();
                try {
                    URI resourceUri = rpBaseUri(rp).resolve("/resource");
                    AuthenticationResponse login = provider.authenticate(OidcProviderTest.request(null,
                            SecurityEnvironment.builder().targetUri(resourceUri).transport("http").build()));
                    assertThat(login.statusCode().orElseThrow(), is(303));
                    UriQuery authorization = UriQuery.create(URI.create(login.responseHeaders().get("Location").getFirst()));
                    assertThat(authorization.first("scope").orElseThrow(), is(adapterScope.orElse("openid accounts.write")));
                    JsonObject.Builder tokenResponse = JsonObject.builder()
                            .from(tokenEndpointResponse(signedIdToken(authorization.first("nonce").orElseThrow())));
                    responseScope.ifPresent(scope -> tokenResponse.set("scope", scope));
                    tokenEndpointResponseBody = tokenResponse.build().toString();
                    String initialCookies = String.join("; ", login.responseHeaders().get("Set-Cookie").stream()
                            .map(SetCookie::parse)
                            .map(cookie -> cookie.name() + "=" + cookie.value())
                            .toList());

                    try (HttpClientResponse callback = client.get().uri(callbackUri(rp))
                            .followRedirects(false)
                            .queryParam("code", "authorization-code")
                            .queryParam("state", authorization.first("state").orElseThrow())
                            .header(HeaderNames.COOKIE, initialCookies)
                            .request()) {
                        assertThat(callback.status(), is(Status.SEE_OTHER_303));
                        SetCookie sessionCookie = localAuthenticationCookie(callback, tenant);
                        AuthenticationResponse authentication = provider.authenticate(OidcProviderTest.request(null,
                                SecurityEnvironment.builder()
                                        .targetUri(resourceUri)
                                        .header(HeaderNames.COOKIE.defaultCase(), initialCookies + "; "
                                                + sessionCookie.name() + "=" + sessionCookie.value())
                                        .build()));
                        assertThat(authentication.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                        assertThat(authentication.user().orElseThrow().grantsByType("scope").stream()
                                           .map(Grant::getName).toList(),
                                   containsInAnyOrder(expectedScopes.toArray(String[]::new)));
                        OidcLocalAuthenticationResult stored = OidcCookieStateHandler.create("default", tenant)
                                .decodeLocalAuthenticationResult(sessionCookie.value(), OidcIdTokenDecryptor.create(tenant))
                                .orElseThrow();
                        assertThat(stored.scope(), is(Optional.of(String.join(" ", expectedScopes))));
                    }
                } finally {
                    rp.stop();
                }
            } finally {
                client.closeResource();
            }
        }
    }

    private static SetCookie authenticationRequestCookie(URI callbackUri, OidcTenantConfig tenant) {
        return authenticationRequestCookie(callbackUri, tenant, URI.create("https://rp.example/resource"));
    }

    private static SetCookie authenticationRequestCookie(URI callbackUri,
                                                        OidcTenantConfig tenant,
                                                        URI originalUri) {
        return authenticationRequestCookie("default", STATE, ISSUER.toString(), callbackUri, tenant, originalUri);
    }

    private static SetCookie authenticationRequestCookie(String tenantId,
                                                         String state,
                                                         String expectedIssuer,
                                                         URI callbackUri,
                                                         OidcTenantConfig tenant) {
        return authenticationRequestCookie(tenantId,
                                           state,
                                           expectedIssuer,
                                           callbackUri,
                                           tenant,
                                           URI.create("https://rp.example/resource"));
    }

    private static SetCookie authenticationRequestCookie(String tenantId,
                                                         String state,
                                                         String expectedIssuer,
                                                         URI callbackUri,
                                                         OidcTenantConfig tenant,
                                                         URI originalUri) {
        Instant now = Instant.now();
        List<String> requestedScopes = tenant.authorizationCode().orElseThrow().scopes();
        return OidcCookieStateHandler.create(tenantId, tenant)
                .createAuthenticationRequestCookies(new OidcAuthenticationRequestState(tenantId,
                                                                                         state,
                                                                                         NONCE,
                                                                                         PKCE_VERIFIER,
                                                                                         null,
                                                                                         expectedIssuer,
                                                                                         originalUri,
                                                                                         callbackUri,
                                                                                         requestedScopes,
                                                                                         now.minusSeconds(1),
                                                                                         now.plusSeconds(60)), false, Map.of())
                .getFirst();
    }

    private static String authorizationState(String tenantId, int requestMarker) {
        byte[] requestId = new byte[32];
        requestId[0] = (byte) requestMarker;
        return OidcAuthorizationState.create(tenantId,
                                             Base64.getUrlEncoder().withoutPadding().encodeToString(requestId))
                .value();
    }

    private static SetCookie localAuthenticationCookie(HttpClientResponse response, OidcTenantConfig tenant) {
        return response.headers()
                .get(HeaderNames.SET_COOKIE)
                .allValues()
                .stream()
                .filter(cookie -> cookie.startsWith(tenant.cookies().localAuthenticationCookieName() + "="))
                .map(SetCookie::parse)
                .findFirst()
                .orElseThrow();
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant, String tenantId) {
        return localAuthenticationCookie(tenant, tenantId, signedIdToken(NONCE));
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant, String tenantId, String rawIdToken) {
        return localAuthenticationCookie(tenant, tenantId, rawIdToken, rawIdToken, false);
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant,
                                                       String tenantId,
                                                       String rawIdToken,
                                                       String signedIdToken,
                                                       boolean encrypted) {
        Instant now = Instant.now();
        SignedJwt signedJwt = SignedJwt.parseToken(signedIdToken);
        OidcValidatedIdToken idToken = new OidcValidatedIdToken(rawIdToken, encrypted, signedJwt, signedJwt.getJwt());
        OidcLocalAuthenticationResult result = OidcLocalAuthenticationResult.fromStoredValues(
                OidcLocalAuthenticationState.builder()
                        .tenantId(tenantId)
                        .idToken(idToken)
                        .accessToken("access-token")
                        .tokenType("Bearer")
                        .scope("openid profile")
                        .createdAt(now.minusSeconds(1))
                        .expiresAt(now.plusSeconds(60))
                        .accessTokenExpiresAt(now.plusSeconds(600))
                        .buildPrototype());
        return OidcCookieStateHandler.create(tenantId, tenant)
                .createLocalAuthenticationResultCookies(result, Map.of(), Instant.now()).getFirst();
    }

    private static String cookieHeader(SetCookie first, SetCookie second) {
        return first.name() + "=" + first.value() + "; " + second.name() + "=" + second.value();
    }

    private static void assertRemovalCookie(List<String> cookies, String name) {
        SetCookie cookie = cookies.stream()
                .filter(it -> it.startsWith(name + "="))
                .map(SetCookie::parse)
                .findFirst()
                .orElseThrow();
        assertThat(cookie.value(), is(""));
        assertThat(cookie.expires().orElseThrow().toInstant(), is(Instant.EPOCH));
        assertThat(cookie.maxAge().orElse(Duration.ZERO), is(Duration.ZERO));
        assertThat(cookie.path().orElse(""), is("/"));
        assertThat(cookie.secure(), is(true));
        assertThat(cookie.httpOnly(), is(true));
        assertThat(cookie.sameSite().orElseThrow(), is(SetCookie.SameSite.LAX));
    }

    private static SetCookie assertBrowserSessionGenerationCookie(List<String> cookies,
                                                                  OidcTenantConfig tenant,
                                                                  String tenantId) {
        OidcCookieStateHandler cookieStateHandler = OidcCookieStateHandler.create(tenantId, tenant);
        SetCookie cookie = cookies.stream()
                .filter(it -> it.startsWith(cookieStateHandler.browserSessionGenerationCookieName() + "="))
                .map(SetCookie::parse)
                .findFirst()
                .orElseThrow();
        assertThat(cookieStateHandler.readBrowserSessionGeneration(cookie.value()).isPresent(), is(true));
        assertThat(cookie.path().orElse(""), is("/"));
        assertThat(cookie.secure(), is(true));
        assertThat(cookie.httpOnly(), is(true));
        assertThat(cookie.sameSite().orElseThrow(), is(SetCookie.SameSite.LAX));
        return cookie;
    }

    private static URI rpBaseUri(WebServer server) {
        return URI.create("http://localhost:" + server.port());
    }

    private static URI issuerUri(WebServer server) {
        return URI.create("http://localhost:" + server.port());
    }

    private static String sameOrigin(WebServer server) {
        return rpBaseUri(server).toString();
    }

    private static URI callbackUri(WebServer server) {
        return rpBaseUri(server).resolve("/oidc/callback");
    }

    private static String signedIdToken(String nonce) {
        return signedIdToken(nonce, ISSUER.toString());
    }

    private static String signedIdToken(String nonce, String issuer) {
        Instant now = Instant.now();
        Jwt jwt = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(issuer)
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .addAudience(CLIENT_ID)
                .nonce(nonce)
                .preferredUsername(USERNAME)
                .email(EMAIL)
                .build();
        return SignedJwt.sign(jwt, signKeys.forKeyId("sign-rsa").orElseThrow())
                .tokenContent();
    }

    private static String signedUserInfo(String subject,
                                         String issuer,
                                         String audience,
                                         Consumer<Jwt.Builder> customizer) {
        return signedUserInfo("RS256", "verify-rsa", subject, issuer, audience, customizer);
    }

    private static String signedUserInfo(String algorithm,
                                         String subject,
                                         String issuer,
                                         String audience,
                                         Consumer<Jwt.Builder> customizer) {
        return signedUserInfo(algorithm, null, subject, issuer, audience, customizer);
    }

    private static String signedUserInfo(String algorithm,
                                         String keyId,
                                         String subject,
                                         String issuer,
                                         String audience,
                                         Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder jwt = Jwt.builder()
                .type("JWT")
                .subject(subject)
                .issuer(issuer)
                .algorithm(algorithm)
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .addAudience(audience);
        if (keyId != null) {
            jwt.keyId(keyId);
        }
        customizer.accept(jwt);
        Jwk signingKey = OidcJoseKeyPolicy.signingKey(signKeys.forKeyId("sign-rsa").orElseThrow(),
                                                      Optional.of(algorithm),
                                                      "test signing JWK");
        return SignedJwt.sign(jwt.build(), signingKey)
                .tokenContent();
    }

    private static String encryptedUserInfo(String subject,
                                            EncryptedJwt.SupportedAlgorithm algorithm,
                                            EncryptedJwt.SupportedEncryption encryption,
                                            JwkKeys keys,
                                            String keyId) {
        JsonObject claims = JsonObject.builder()
                .set("sub", subject)
                .set("preferred_username", "userinfo-user")
                .setStrings("groups", List.of("admin", "auditor"))
                .build();
        return encryptedPayload(claims.toString().getBytes(StandardCharsets.UTF_8),
                                algorithm,
                                encryption,
                                keys,
                                keyId);
    }

    private static String encryptedPayload(byte[] payload,
                                           EncryptedJwt.SupportedAlgorithm algorithm,
                                           EncryptedJwt.SupportedEncryption encryption,
                                           JwkKeys keys,
                                           String keyId) {
        return EncryptedJwt.payloadBuilder(payload)
                .jwks(keys, keyId)
                .algorithm(algorithm)
                .encryption(encryption)
                .build()
                .token();
    }

    private static String encryptedSignedUserInfo(String subject,
                                                  EncryptedJwt.SupportedAlgorithm algorithm,
                                                  EncryptedJwt.SupportedEncryption encryption) {
        String signed = signedUserInfo(subject, ISSUER.toString(), CLIENT_ID, jwt -> jwt
                .preferredUsername("userinfo-user")
                .addUserGroup("admin")
                .addUserGroup("auditor"));
        return encryptedSignedPayload(signed, algorithm, encryption);
    }

    private static String encryptedSignedPayload(String signed,
                                                 EncryptedJwt.SupportedAlgorithm algorithm,
                                                 EncryptedJwt.SupportedEncryption encryption) {
        return EncryptedJwt.builder(SignedJwt.parseToken(signed))
                .jwks(encryptKeys, "encrypt-rsa")
                .algorithm(algorithm)
                .encryption(encryption)
                .build()
                .token();
    }

    private static String unsignedUserInfo() {
        Instant now = Instant.now();
        Jwt jwt = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(ISSUER.toString())
                .algorithm(Jwk.ALG_NONE)
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .addAudience(CLIENT_ID)
                .build();
        return SignedJwt.sign(jwt, Jwk.NONE_JWK)
                .tokenContent();
    }

    private static String tamperedSignature(String jwt) {
        String[] parts = jwt.split("\\.", -1);
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        signature[0] ^= 1;
        parts[2] = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        return String.join(".", parts);
    }

    private static String tamperedAuthenticationTag(String jwt) {
        String[] parts = jwt.split("\\.", -1);
        byte[] authenticationTag = Base64.getUrlDecoder().decode(parts[4]);
        authenticationTag[0] ^= 1;
        parts[4] = Base64.getUrlEncoder().withoutPadding().encodeToString(authenticationTag);
        return String.join(".", parts);
    }

    private static String encryptedIdToken(String signedIdToken) {
        return EncryptedJwt.builder(SignedJwt.parseToken(signedIdToken))
                .jwks(encryptKeys, "encrypt-rsa")
                .build()
                .token();
    }

}
