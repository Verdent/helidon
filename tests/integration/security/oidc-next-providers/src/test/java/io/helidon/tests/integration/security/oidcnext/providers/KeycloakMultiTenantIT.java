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

package io.helidon.tests.integration.security.oidcnext.providers;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import io.helidon.common.uri.UriQuery;
import io.helidon.common.uri.UriQueryWriteable;
import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.Method;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.Security;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.providers.oidc.next.OidcClientAuthenticationMethod;
import io.helidon.security.providers.oidc.next.OidcCookieConfig;
import io.helidon.security.providers.oidc.next.OidcEndpointCredential;
import io.helidon.security.providers.oidc.next.OidcEndpointPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcFeature;
import io.helidon.security.providers.oidc.next.OidcProvider;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcPushedAuthorizationRequestMode;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.security.SecurityFeature;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.DockerClientFactory;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class KeycloakMultiTenantIT {
    private static final String FIRST = "first";
    private static final String SECOND = "second";
    private static final String CALLBACK = "/oidc/callback";
    private static final String STATE_COOKIE = "__Host-helidon-oidc-state-";
    private static final String SESSION_COOKIE = "__Host-helidon-oidc-auth-";
    private static final HeaderName TENANT_HEADER = HeaderNames.create("X-Tenant");
    private static final IdpAdapter.ClientMode FIRST_CLIENT = IdpAdapter.ClientMode.JWT_ACCESS;
    private static final IdpAdapter.ClientMode SECOND_CLIENT = IdpAdapter.ClientMode.BASIC;
    private static final String BACK_CHANNEL = "/oidc/backchannel/";

    private KeycloakAdapter first;
    private KeycloakAdapter second;

    @BeforeAll
    void startProviders() throws Exception {
        assumeTrue(DockerClientFactory.instance().isDockerAvailable(), "Provider integration tests require Docker");
        first = new KeycloakAdapter();
        // A different SAN-covered hostname keeps the two OPs' browser cookies separate (cookies ignore ports).
        second = new KeycloakAdapter("auth.authelia.test");
        try {
            first.start();
            second.start();
        } catch (Exception failure) {
            try {
                stopProviders();
            } catch (RuntimeException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            throw failure;
        }
    }

    @AfterAll
    void stopProviders() {
        try {
            if (second != null) {
                second.close();
            }
        } finally {
            if (first != null) {
                first.close();
            }
        }
    }

    @Test
    void overlappingLoginsAndConflictingTenantSelectorsUseTheSelectedTenantsConfiguration() throws Exception {
        try (TenantRelyingParty rp = relyingParty(FIRST_CLIENT, SECOND_CLIENT,
                                                 OidcTokenValidationMethod.JWT, OidcTokenValidationMethod.INTROSPECTION);
             TestBrowser browser = new TestBrowser(first.webClient())) {
            registerCallbacks(rp, FIRST_CLIENT, SECOND_CLIENT);
            // Two different client registrations and two access-token validation modes share one RP and callback.
            URI firstAuthorization = authorization(browser, rp, FIRST, first, FIRST_CLIENT);
            URI secondAuthorization = authorization(browser, rp, SECOND, second, SECOND_CLIENT);
            assertThat(browser.cookieValue(STATE_COOKIE + FIRST).isPresent(), is(true));
            assertThat(browser.cookieValue(STATE_COOKIE + SECOND).isPresent(), is(true));
            URI firstCallback = first.login(browser, firstAuthorization, rp.callback());
            URI secondCallback = second.login(browser, secondAuthorization, rp.callback());
            // Callback selection must follow the protected state, even when a request header points elsewhere.
            completeWithTenantHeader(browser, secondCallback, FIRST);
            completeWithTenantHeader(browser, firstCallback, SECOND);

            assertThat(browser.cookieValue(SESSION_COOKIE + FIRST).isPresent(), is(true));
            assertThat(browser.cookieValue(SESSION_COOKIE + SECOND).isPresent(), is(true));
            JsonObject firstSession = resource(browser, rp, FIRST);
            JsonObject secondSession = resource(browser, rp, SECOND);
            assertThat(firstSession.stringValue("name").orElseThrow(), is("alice"));
            assertThat(secondSession.stringValue("name").orElseThrow(), is("alice"));
            String firstId = firstSession.stringValue("id").orElseThrow();
            String secondId = secondSession.stringValue("id").orElseThrow();
            assertThat("Identical native sub values from different issuers must remain distinct users",
                       firstId, not(secondId));

            String firstToken = firstSession.stringValue("access_token").orElseThrow();
            String secondToken = secondSession.stringValue("access_token").orElseThrow();
            var firstJwt = SignedJwt.parseToken(firstToken).getJwt();
            var secondJwt = SignedJwt.parseToken(secondToken).getJwt();
            assertThat(firstJwt.subject(), is(secondJwt.subject()));
            assertThat(firstJwt.issuer().orElseThrow(), is(first.issuer().toString()));
            assertThat(secondJwt.issuer().orElseThrow(), is(second.issuer().toString()));
            assertThat(firstJwt.payloadClaimValue("azp").orElseThrow().asString().value(), is(FIRST_CLIENT.id()));
            assertThat(secondJwt.payloadClaimValue("azp").orElseThrow().asString().value(), is(SECOND_CLIENT.id()));

            // The header is intentionally higher priority than the path. Prove that the credentials and selected
            // validation policy follow the resolved tenant, not the URL of the resource being served.
            WebClient client = WebClient.builder().from(first.webClient()).followRedirects(false).build();
            try {
                assertBearer(client, rp.uri(FIRST, "api"), firstToken, Status.OK_200, firstId);
                assertBearer(client, rp.uri(SECOND, "api"), secondToken, Status.OK_200, secondId);
                assertBearer(client, rp.uri(FIRST, "api"), secondToken, Status.UNAUTHORIZED_401, null);
                assertBearer(client, rp.uri(SECOND, "api"), firstToken, Status.UNAUTHORIZED_401, null);
                assertBearerWithHeader(client, rp.uri(FIRST, "api"), secondToken, SECOND, Status.OK_200, secondId);
                assertBearerWithHeader(client, rp.uri(FIRST, "api"), firstToken, SECOND, Status.UNAUTHORIZED_401, null);
                assertBearerWithHeader(client, rp.uri(SECOND, "api"), firstToken, FIRST, Status.OK_200, firstId);
                assertBearerWithHeader(client, rp.uri(SECOND, "api"), secondToken, FIRST, Status.UNAUTHORIZED_401, null);
                assertBearerWithHeader(client, rp.uri(FIRST, "api"), firstToken, "unknown", Status.UNAUTHORIZED_401, null);
                for (boolean renamed : List.of(false, true)) {
                    assertCookieIsNotAnotherTenantsSession(client, rp, FIRST, SECOND, browser, renamed);
                    assertCookieIsNotAnotherTenantsSession(client, rp, SECOND, FIRST, browser, renamed);
                }
                // Selection also controls the browser redirect and the state-cookie namespace before login.
                try (HttpClientResponse response = client.get().uri(rp.uri(FIRST, "resource"))
                        .header(TENANT_HEADER, SECOND).request()) {
                    assertThat(response.status(), is(Status.SEE_OTHER_303));
                    URI authorization = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                    assertThat(authorization.getAuthority(), is(second.issuer().getAuthority()));
                    assertThat(UriQuery.create(authorization).first("client_id").orElseThrow(), is(SECOND_CLIENT.id()));
                    assertThat(response.headers().get(HeaderNames.SET_COOKIE).allValues().stream()
                                       .anyMatch(cookie -> cookie.startsWith(STATE_COOKIE + SECOND + "=")), is(true));
                }
            } finally {
                client.closeResource();
            }
        }
    }

    @Test
    void responseFromSecondIssuerCannotCompleteFirstTenantsLogin() throws Exception {
        IdpAdapter.ClientMode mode = IdpAdapter.ClientMode.BASIC;
        try (TenantRelyingParty rp = relyingParty(mode, OidcTokenValidationMethod.INTROSPECTION);
             TestBrowser browser = new TestBrowser(first.webClient())) {
            registerCallbacks(rp, mode);
            URI firstAuthorization = authorization(browser, rp, FIRST, first, mode);
            URI secondAuthorization = authorization(browser, rp, SECOND, second, mode);
            URI firstCallback = first.login(browser, firstAuthorization, rp.callback());
            URI secondCallback = second.login(browser, secondAuthorization, rp.callback());

            // Both are genuine Keycloak responses. Only the state is swapped; iss and code remain from the second OP.
            String firstState = UriQuery.create(firstCallback).first("state").orElseThrow();
            UriQueryWriteable query = UriQueryWriteable.create().from(UriQuery.create(secondCallback));
            query.set("state", firstState);
            URI mixedCallback = URI.create(rp.callback() + "?" + query.rawValue());
            try (HttpClientResponse response = browser.get(mixedCallback)) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
            }
            assertThat(browser.cookieValue(SESSION_COOKIE + FIRST).isEmpty(), is(true));
            assertThat(browser.cookieValue(SESSION_COOKIE + SECOND).isEmpty(), is(true));

            // A rejected response for the first tenant must not consume the second tenant's legitimate transaction.
            complete(browser, secondCallback);
            assertThat(resource(browser, rp, SECOND).stringValue("name").orElseThrow(), is("alice"));
            assertThat(browser.cookieValue(SESSION_COOKIE + FIRST).isEmpty(), is(true));
        }
    }

    @Test
    void backChannelLogoutRevokesOnlyTheIssuingTenantsSession() throws Exception {
        try (TenantRelyingParty rp = relyingParty(FIRST_CLIENT, SECOND_CLIENT,
                                                 OidcTokenValidationMethod.JWT,
                                                 OidcTokenValidationMethod.INTROSPECTION, true);
             TestBrowser browser = new TestBrowser(first.webClient())) {
            registerCallbacks(rp, FIRST_CLIENT, SECOND_CLIENT);
            try (AutoCloseable firstRegistration = first.registerBackChannelLogout(FIRST_CLIENT,
                                                                                   rp.backChannelUri(FIRST), true);
                 AutoCloseable secondRegistration = second.registerBackChannelLogout(SECOND_CLIENT,
                                                                                     rp.backChannelUri(SECOND), true)) {
                complete(browser, first.login(browser, authorization(browser, rp, FIRST, first, FIRST_CLIENT),
                                              rp.callback()));
                complete(browser, second.login(browser, authorization(browser, rp, SECOND, second, SECOND_CLIENT),
                                               rp.callback()));
                String firstId = resource(browser, rp, FIRST).stringValue("id").orElseThrow();
                String secondId = resource(browser, rp, SECOND).stringValue("id").orElseThrow();

                // Both OPs have the same sub; only the issuer's own signed notification may revoke its session.
                first.logoutUser("alice");
                assertThat(rp.awaitBackChannel(FIRST), is(Status.OK_200));
                try (HttpClientResponse response = browser.get(rp.uri(FIRST, "resource"))) {
                    assertThat(response.status(), is(Status.SEE_OTHER_303));
                }
                assertThat(browser.cookieValue(SESSION_COOKIE + FIRST).isEmpty(), is(true));
                assertThat(resource(browser, rp, SECOND).stringValue("id").orElseThrow(), is(secondId));
                assertThat(rp.logoutDeliveries().get(BACK_CHANNEL + SECOND).isDone(), is(false));

                second.logoutUser("alice");
                assertThat(rp.awaitBackChannel(SECOND), is(Status.OK_200));
                try (HttpClientResponse response = browser.get(rp.uri(SECOND, "resource"))) {
                    assertThat(response.status(), is(Status.SEE_OTHER_303));
                }
                assertThat(browser.cookieValue(SESSION_COOKIE + SECOND).isEmpty(), is(true));
                assertThat(firstId, not(secondId));
            }
        }
    }

    @Test
    void refreshingOneTenantDoesNotReplaceTheOtherTenantsSession() throws Exception {
        IdpAdapter.ClientMode shortLived = IdpAdapter.ClientMode.SHORT_LIVED;
        try (TenantRelyingParty rp = relyingParty(shortLived, SECOND_CLIENT,
                                                 OidcTokenValidationMethod.JWT,
                                                 OidcTokenValidationMethod.INTROSPECTION);
             TestBrowser browser = new TestBrowser(first.webClient())) {
            registerCallbacks(rp, shortLived, SECOND_CLIENT);
            complete(browser, first.login(browser, authorization(browser, rp, FIRST, first, shortLived), rp.callback()));
            complete(browser, second.login(browser, authorization(browser, rp, SECOND, second, SECOND_CLIENT),
                                           rp.callback()));
            String firstCookie = browser.cookieValue(SESSION_COOKIE + FIRST).orElseThrow();
            String secondCookie = browser.cookieValue(SESSION_COOKIE + SECOND).orElseThrow();

            // The first access token expires within the renewal margin; its refresh must use the first OP's
            // credentials and token endpoint without consuming or replacing the second tenant's browser session.
            JsonObject renewed = resource(browser, rp, FIRST);
            assertThat(browser.cookieValue(SESSION_COOKIE + FIRST).orElseThrow(), not(firstCookie));
            assertThat(browser.cookieValue(SESSION_COOKIE + SECOND).orElseThrow(), is(secondCookie));
            assertThat(SignedJwt.parseToken(renewed.stringValue("access_token").orElseThrow()).getJwt()
                               .issuer().orElseThrow(), is(first.issuer().toString()));

            JsonObject unaffected = resource(browser, rp, SECOND);
            assertThat(browser.cookieValue(SESSION_COOKIE + SECOND).orElseThrow(), is(secondCookie));
            assertThat(SignedJwt.parseToken(unaffected.stringValue("access_token").orElseThrow()).getJwt()
                               .issuer().orElseThrow(), is(second.issuer().toString()));
        }
    }

    private static void assertBearer(WebClient client, URI resource, String token, Status expected, String expectedId) {
        try (HttpClientResponse response = client.get().uri(resource)
                .header(HeaderNames.AUTHORIZATION, "Bearer " + token).request()) {
            assertThat(response.status(), is(expected));
            if (expectedId != null) {
                assertThat(response.as(JsonObject.class).stringValue("id").orElseThrow(), is(expectedId));
            }
        }
    }

    private static void assertBearerWithHeader(WebClient client, URI resource, String token, String selectedTenant,
                                               Status expected, String expectedId) {
        try (HttpClientResponse response = client.get().uri(resource)
                .header(HeaderNames.AUTHORIZATION, "Bearer " + token)
                .header(TENANT_HEADER, selectedTenant).request()) {
            assertThat(response.status(), is(expected));
            if (expectedId != null) {
                assertThat(response.as(JsonObject.class).stringValue("id").orElseThrow(), is(expectedId));
            }
        }
    }

    private static void assertCookieIsNotAnotherTenantsSession(WebClient client, TenantRelyingParty rp, String owner,
                                                                String target, TestBrowser browser, boolean renamed) {
        // Supply the complete cookie family (including chunking and generation). Renaming it to the target tenant's
        // cookie names must still fail: the protected payload is cryptographically bound to its original tenant.
        String ownerName = SESSION_COOKIE + owner;
        String requestName = SESSION_COOKIE + (renamed ? target : owner);
        StringJoiner cookies = new StringJoiner("; ");
        for (int chunk = 0; chunk < OidcCookieConfig.create().maxChunks(); chunk++) {
            String suffix = chunk == 0 ? "" : "." + chunk;
            String destination = requestName + suffix;
            browser.cookieValue(ownerName + suffix).ifPresent(value -> cookies.add(destination + "=" + value));
        }
        cookies.add(requestName + "-generation=" + browser.cookieValue(ownerName + "-generation").orElseThrow());
        try (HttpClientResponse response = client.get().uri(rp.uri(target, "resource"))
                .header(HeaderNames.COOKIE, cookies.toString()).request()) {
            assertThat(response.status(), is(Status.SEE_OTHER_303));
        }
    }

    private static URI authorization(TestBrowser browser, TenantRelyingParty rp, String tenant, KeycloakAdapter adapter,
                                     IdpAdapter.ClientMode mode)
            throws Exception {
        try (HttpClientResponse response = browser.get(rp.uri(tenant, "resource"))) {
            assertThat(response.status(), is(Status.SEE_OTHER_303));
            URI authorization = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
            assertThat(authorization.getAuthority(), is(adapter.issuer().getAuthority()));
            assertThat(UriQuery.create(authorization).first("client_id").orElseThrow(), is(mode.id()));
            assertThat(UriQuery.create(authorization).first("scope").orElseThrow(), is(String.join(" ", scopes(tenant, mode))));
            assertThat(UriQuery.create(authorization).first("code_challenge_method").orElseThrow(), is("S256"));
            return authorization;
        }
    }

    private static void complete(TestBrowser browser, URI callback) throws Exception {
        try (HttpClientResponse response = browser.get(callback)) {
            assertThat(response.status(), is(Status.SEE_OTHER_303));
        }
    }

    private static void completeWithTenantHeader(TestBrowser browser, URI callback, String headerTenant) throws Exception {
        try (HttpClientResponse response = browser.get(callback, request -> request.header(TENANT_HEADER, headerTenant))) {
            assertThat(response.status(), is(Status.SEE_OTHER_303));
        }
    }

    private static JsonObject resource(TestBrowser browser, TenantRelyingParty rp, String tenant) throws Exception {
        try (HttpClientResponse response = browser.get(rp.uri(tenant, "resource"))) {
            assertThat(response.status(), is(Status.OK_200));
            return response.as(JsonObject.class);
        }
    }

    private void registerCallbacks(TenantRelyingParty rp, IdpAdapter.ClientMode mode) {
        registerCallbacks(rp, mode, mode);
    }

    private void registerCallbacks(TenantRelyingParty rp, IdpAdapter.ClientMode firstMode,
                                   IdpAdapter.ClientMode secondMode) {
        first.registerCallback(firstMode, rp.callback());
        second.registerCallback(secondMode, rp.callback());
    }

    private TenantRelyingParty relyingParty(IdpAdapter.ClientMode mode, OidcTokenValidationMethod method) {
        return relyingParty(mode, mode, method, method);
    }

    private TenantRelyingParty relyingParty(IdpAdapter.ClientMode firstMode, IdpAdapter.ClientMode secondMode,
                                            OidcTokenValidationMethod firstMethod, OidcTokenValidationMethod secondMethod) {
        return relyingParty(firstMode, secondMode, firstMethod, secondMethod, false);
    }

    private TenantRelyingParty relyingParty(IdpAdapter.ClientMode firstMode, IdpAdapter.ClientMode secondMode,
                                            OidcTokenValidationMethod firstMethod, OidcTokenValidationMethod secondMethod,
                                            boolean backChannelLogout) {
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant(FIRST, tenant(first, FIRST, firstMode, firstMethod, backChannelLogout))
                .putTenant(SECOND, tenant(second, SECOND, secondMode, secondMethod, backChannelLogout))
                .tenantResolution(resolution -> resolution.headerName("X-Tenant").pathSegment(0)).buildPrototype();
        OidcProvider provider = OidcProvider.create(config);
        HttpRouting.Builder routing = HttpRouting.builder();
        Map<String, CompletableFuture<Status>> logoutDeliveries = backChannelLogout
                ? Map.of(BACK_CHANNEL + FIRST, new CompletableFuture<>(),
                         BACK_CHANNEL + SECOND, new CompletableFuture<>()) : Map.of();
        if (backChannelLogout) {
            routing.addFilter((chain, request, response) -> {
                CompletableFuture<Status> delivery = logoutDeliveries.get(request.requestedUri().toUri().getPath());
                if (request.prologue().method() == Method.POST && delivery != null) {
                    try {
                        chain.proceed();
                    } finally {
                        delivery.complete(response.status());
                    }
                } else {
                    chain.proceed();
                }
            });
        }
        OidcFeature.create(provider).setup(routing);
        OidcEndpointPolicyConfig cookiePolicy = OidcEndpointPolicyConfig.builder()
                .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE)).buildPrototype();
        OidcEndpointPolicyConfig bearerPolicy = OidcEndpointPolicyConfig.builder()
                .acceptedCredentials(List.of(OidcEndpointCredential.BEARER_TOKEN)).buildPrototype();
        for (String tenant : List.of(FIRST, SECOND)) {
            routing.get("/" + tenant + "/resource", SecurityFeature.authenticate().customObject(cookiePolicy),
                        (_, response) -> response.send(RelyingParty.subject()));
            routing.get("/" + tenant + "/api", SecurityFeature.authenticate().customObject(bearerPolicy),
                        (_, response) -> response.send(RelyingParty.subject()));
        }
        try {
            WebServer server = WebServer.builder().host(backChannelLogout ? "0.0.0.0" : "127.0.0.1")
                    .port(0).tls(IdpResources.serverTls())
                    .addFeature(SecurityFeature.builder().security(Security.builder()
                            .addProvider(provider, "oidc-next").build()).build())
                    .addRouting(routing).build().start();
            return new TenantRelyingParty(provider, server, logoutDeliveries);
        } catch (RuntimeException failure) {
            provider.close();
            throw failure;
        }
    }

    private static OidcTenantConfig tenant(KeycloakAdapter adapter, String tenant, IdpAdapter.ClientMode mode,
                                           OidcTokenValidationMethod method, boolean backChannelLogout) {
        OidcTenantConfig.Builder builder = OidcTenantConfig.builder().issuer(adapter.issuer().toString()).clientId(mode.id())
                .clientSecret(IdpAdapter.SECRET).webClient(adapter.webClient())
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationCode(code -> code.scopes(scopes(tenant, mode))
                        .pushedAuthorizationRequests(OidcPushedAuthorizationRequestMode.DISABLED))
                .protectedResource(resource -> resource.tokenValidation(validation -> {
                    validation.method(method).audience(IdpAdapter.AUDIENCE)
                            .introspection(introspection -> introspection.clientId(IdpAdapter.ClientMode.API.id())
                                    .clientSecret(IdpAdapter.SECRET));
                    if (method == OidcTokenValidationMethod.JWT) {
                        validation.jwt(adapter.jwtLayout());
                    }
                }))
                // Use the same password on purpose; encryption must still keep tenants separate.
                .cookies(cookies -> cookies.password("integration-test-authentication-cookie-password")
                        .authenticationRequestCookieName(STATE_COOKIE + tenant)
                        .localAuthenticationCookieName(SESSION_COOKIE + tenant));
        if (backChannelLogout) {
            builder.logout(logout -> logout.backChannel(backChannel -> backChannel
                    .uri(URI.create("https://auth.authelia.test" + BACK_CHANNEL + tenant)).sessionRequired(true)));
        }
        return builder.buildPrototype();
    }

    private static List<String> scopes(String tenant, IdpAdapter.ClientMode mode) {
        if (mode == IdpAdapter.ClientMode.SHORT_LIVED) {
            return List.of("openid", "profile", "email", "resource.read", "offline_access");
        }
        return FIRST.equals(tenant) ? List.of("openid", "profile", "email", "resource.read")
                : List.of("openid", "profile", "groups", "resource.read");
    }

    private record TenantRelyingParty(OidcProvider provider, WebServer server,
                                     Map<String, CompletableFuture<Status>> logoutDeliveries) implements AutoCloseable {
        URI baseUri() {
            return URI.create("https://localhost:" + server.port());
        }

        URI callback() {
            return baseUri().resolve(CALLBACK);
        }

        URI uri(String tenant, String resource) {
            return baseUri().resolve("/" + tenant + "/" + resource);
        }

        URI backChannelUri(String tenant) {
            return URI.create("https://auth.authelia.test:" + server.port() + BACK_CHANNEL + tenant);
        }

        Status awaitBackChannel(String tenant) throws Exception {
            return logoutDeliveries.get(BACK_CHANNEL + tenant).get(30, TimeUnit.SECONDS);
        }

        @Override
        public void close() {
            try {
                server.stop();
            } finally {
                provider.close();
            }
        }
    }
}
