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
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.Grant;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.common.TokenCredential;
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
import static org.hamcrest.Matchers.containsString;

@ServerTest
class OidcFeatureRouteTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI CONFIGURED_REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final String COOKIE_SECRET = "test-cookie-secret";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_SECRET = "client-secret";
    private static final String SUBJECT = "user1-id";
    private static final String USERNAME = "user1";
    private static final String EMAIL = "user1@example.org";
    private static final String STATE = "stored-state";
    private static final String NONCE = "nonce";
    private static final String PKCE_VERIFIER = "pkce-verifier";

    private static JwkKeys signKeys;
    private static String verifyJwkSet;
    private static String tokenEndpointResponseBody;

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        verifyJwkSet = Resource.create("oidc-next-verify-jwk.json").string();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        OidcFeature.create(providerConfig()).setup(routing);
        routing.post("/token", (request, response) -> tokenEndpointResponse(response));
        routing.get("/jwks", (request, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(verifyJwkSet));
    }

    @BeforeEach
    void setUp() {
        tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken(NONCE)).toString();
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
    void redirectionEndpointRouteHandlesAuthorizationErrorBeforeTokenExchange(WebClient client, URI serverUri) {
        Instant now = Instant.now();
        URI callbackUri = serverUri.resolve("oidc/callback");
        SetCookie stateCookie = OidcCookieStateHandler.create(tenantConfig())
                .createAuthenticationRequestCookie(OidcAuthenticationRequestState.create("default",
                                                                                         "stored-state",
                                                                                         "nonce",
                                                                                         "pkce-verifier",
                                                                                         serverUri.resolve("resource"),
                                                                                         callbackUri,
                                                                                         now.minusSeconds(1),
                                                                                         now.plusSeconds(60)));

        try (HttpClientResponse response = client.get("/oidc/callback")
                .queryParam("error", "access_denied")
                .queryParam("state", "stored-state")
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
    void redirectionEndpointRouteValidatesIdToken(URI serverUri) {
        WebServer rpServer = redirectionEndpointServer(serverUri);
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
                           is("https://rp.example/resource"));

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
                assertThat(subject.principal().id(), is(SUBJECT));
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
    void redirectionEndpointRouteRejectsInvalidIdToken(URI serverUri) {
        tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken("other-nonce")).toString();
        WebServer rpServer = redirectionEndpointServer(serverUri);
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

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .post("/oidc/logout")
                    .header(HeaderNames.ORIGIN, sameOrigin(rpServer))
                    .header(HeaderNames.COOKIE, cookieHeader(localAuthenticationCookie, authenticationRequestCookie))
                    .request()) {
                assertThat(response.status(), is(Status.NO_CONTENT_204));

                List<String> cookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
                assertThat(cookies.size(), is(2));
                assertRemovalCookie(cookies, tenant.cookies().localAuthenticationCookieName());
                assertRemovalCookie(cookies, tenant.cookies().authenticationRequestCookieName());
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
        OidcTenantConfig tenantA = tenantConfigWithLogout("state-a", "auth", "shared-cookie-secret");
        OidcTenantConfig tenantB = tenantConfigWithLogout("state-b", "auth", "shared-cookie-secret");
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
                assertThat(cookies.size(), is(2));
                assertRemovalCookie(cookies, "auth");
                assertRemovalCookie(cookies, "state-b");
                assertThat(cookies.stream().noneMatch(cookie -> cookie.startsWith("state-a=")), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteClearsAllPathTenantsWhenLocalAuthenticationCookieTenantIsAmbiguous() {
        OidcTenantConfig tenantA = tenantConfigWithLogout("state-a", "auth-a", "tenant-a-secret");
        OidcTenantConfig tenantB = tenantConfigWithLogout("state-b", "auth-b", "tenant-b-secret");
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
                assertThat(cookies.size(), is(4));
                assertRemovalCookie(cookies, "auth-a");
                assertRemovalCookie(cookies, "state-a");
                assertRemovalCookie(cookies, "auth-b");
                assertRemovalCookie(cookies, "state-b");
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteClearsAllLogoutTenantCookiesWhenTenantIsUnresolved() {
        OidcTenantConfig tenantA = tenantConfigWithLogout("state-a", "auth-a", "tenant-a-secret");
        OidcTenantConfig tenantB = tenantConfigWithLogout("state-b", "auth-b", "tenant-b-secret");
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
                assertThat(cookies.size(), is(4));
                assertRemovalCookie(cookies, "auth-a");
                assertRemovalCookie(cookies, "state-a");
                assertRemovalCookie(cookies, "auth-b");
                assertRemovalCookie(cookies, "state-b");
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void logoutEndpointRouteFallbackUsesOnlyRequestedPathTenants() {
        OidcTenantConfig tenantA = tenantConfigWithLogout("state-a",
                                                          "auth-a",
                                                          "tenant-a-secret",
                                                          logout -> logout.localEndpointUri(URI.create("/oidc/logout-a")));
        OidcTenantConfig tenantB = tenantConfigWithLogout("state-b",
                                                          "auth-b",
                                                          "tenant-b-secret",
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
                assertThat(cookies.size(), is(2));
                assertRemovalCookie(cookies, "auth-a");
                assertRemovalCookie(cookies, "state-a");
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

    private static OidcProviderConfig providerConfig() {
        return OidcProviderConfig.builder()
                .putTenant("default", tenantConfig())
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
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfigWithLogout() {
        return tenantConfigWithLogout(logout -> { });
    }

    private static OidcTenantConfig tenantConfigWithLogout(Consumer<OidcLogoutConfig.Builder> logout) {
        return tenantConfigWithLogout("__Host-helidon-oidc-state",
                                      "__Host-helidon-oidc-auth",
                                      COOKIE_SECRET,
                                      logout);
    }

    private static OidcTenantConfig tenantConfigWithLogout(String authenticationRequestCookieName,
                                                          String localAuthenticationCookieName,
                                                          String cookieSecret) {
        return tenantConfigWithLogout(authenticationRequestCookieName,
                                      localAuthenticationCookieName,
                                      cookieSecret,
                                      logout -> { });
    }

    private static OidcTenantConfig tenantConfigWithLogout(String authenticationRequestCookieName,
                                                          String localAuthenticationCookieName,
                                                          String cookieSecret,
                                                          Consumer<OidcLogoutConfig.Builder> logout) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .logout(logout)
                .cookies(it -> it.authenticationRequestCookieName(authenticationRequestCookieName)
                        .localAuthenticationCookieName(localAuthenticationCookieName)
                        .encryptionSecret(cookieSecret))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfig(URI openIdProviderUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(openIdProviderUri.resolve("token"))
                        .jwksUri(openIdProviderUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static void tokenEndpointResponse(ServerResponse response) {
        response.header(HeaderValues.CONTENT_TYPE_JSON)
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

    private static WebServer redirectionEndpointServer(URI openIdProviderUri) {
        return oidcFeatureServer(providerConfig(openIdProviderUri));
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

    private static SetCookie authenticationRequestCookie(URI callbackUri, OidcTenantConfig tenant) {
        Instant now = Instant.now();
        URI originalUri = URI.create("https://rp.example/resource");
        return OidcCookieStateHandler.create(tenant)
                .createAuthenticationRequestCookie(OidcAuthenticationRequestState.create("default",
                                                                                         STATE,
                                                                                         NONCE,
                                                                                         PKCE_VERIFIER,
                                                                                         originalUri,
                                                                                         callbackUri,
                                                                                         now.minusSeconds(1),
                                                                                         now.plusSeconds(60)));
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant, String tenantId) {
        Instant now = Instant.now();
        String rawIdToken = signedIdToken(NONCE);
        SignedJwt signedJwt = SignedJwt.parseToken(rawIdToken);
        OidcValidatedIdToken idToken = OidcValidatedIdToken.create(rawIdToken, signedJwt, signedJwt.getJwt());
        OidcLocalAuthenticationResult result = OidcLocalAuthenticationResult.create(tenantId,
                                                                                   idToken,
                                                                                   "access-token",
                                                                                   "Bearer",
                                                                                   null,
                                                                                   "openid profile",
                                                                                   now.minusSeconds(1),
                                                                                   now.plusSeconds(60),
                                                                                   now.plusSeconds(600));
        return OidcCookieStateHandler.create(tenant)
                .createLocalAuthenticationResultCookie(result);
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

    private static URI rpBaseUri(WebServer server) {
        return URI.create("http://localhost:" + server.port());
    }

    private static String sameOrigin(WebServer server) {
        return rpBaseUri(server).toString();
    }

    private static URI callbackUri(WebServer server) {
        return rpBaseUri(server).resolve("/oidc/callback");
    }

    private static String signedIdToken(String nonce) {
        Instant now = Instant.now();
        Jwt jwt = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(ISSUER.toString())
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
}
