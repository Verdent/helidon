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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.AllowList;
import io.helidon.common.configurable.Resource;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.RequestedUriDiscoveryContext;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.Grant;
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
import static org.junit.jupiter.api.Assertions.assertThrows;

@ServerTest
class OidcFeatureRouteTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI END_SESSION_ENDPOINT_URI = URI.create("https://issuer.example/logout");
    private static final URI CONFIGURED_REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI POST_LOGOUT_REDIRECT_URI = URI.create("https://rp.example/logged-out");
    private static final URI OTHER_POST_LOGOUT_REDIRECT_URI = URI.create("https://rp.example/other-logged-out");
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
    private static JwkKeys encryptKeys;
    private static String verifyJwkSet;
    private static String tokenEndpointResponseBody;
    private static String userInfoEndpointResponseBody;
    private static Status userInfoEndpointStatus;
    private static String userInfoEndpointContentType;
    private static final AtomicReference<String> USER_INFO_AUTHORIZATION = new AtomicReference<>();

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        encryptKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-encrypt-jwk.json"))
                .build();
        verifyJwkSet = Resource.create("oidc-next-verify-jwk.json").string();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        OidcFeature.create(providerConfig()).setup(routing);
        routing.post("/token", (request, response) -> tokenEndpointResponse(response));
        routing.get("/userinfo", (request, response) -> {
            USER_INFO_AUTHORIZATION.set(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""));
            response.status(userInfoEndpointStatus);
            if (userInfoEndpointStatus.family() == Status.Family.SUCCESSFUL && userInfoEndpointContentType != null) {
                response.header(HeaderNames.CONTENT_TYPE, userInfoEndpointContentType);
            }
            response.send(userInfoEndpointResponseBody);
        });
        routing.get("/jwks", (request, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(verifyJwkSet));
    }

    @BeforeEach
    void setUp() {
        tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken(NONCE)).toString();
        userInfoEndpointResponseBody = userInfoEndpointResponse(SUBJECT).build().toString();
        userInfoEndpointStatus = Status.OK_200;
        userInfoEndpointContentType = "application/json";
        USER_INFO_AUTHORIZATION.set("");
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
        SetCookie stateCookie = OidcCookieStateHandler.create(tenantConfig())
                .createAuthenticationRequestCookie(new OidcAuthenticationRequestState("default",
                                                                                         "stored-state",
                                                                                         "nonce",
                                                                                         "pkce-verifier",
                                                                                         ISSUER.toString(),
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
                JsonObject storedUserInfo = OidcCookieStateHandler.create(tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value())
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
                                                                   .decryptionJwk(Resource.create(
                                                                           "oidc-next-encrypt-jwk.json"))));
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
                JsonObject storedUserInfo = OidcCookieStateHandler.create(tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value())
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
                                                                   .decryptionJwk(Resource.create(
                                                                           "oidc-next-encrypt-jwk.json"))));
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
                JsonObject storedUserInfo = OidcCookieStateHandler.create(tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value())
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
        userInfoEndpointResponseBody = signedUserInfo(SUBJECT, ISSUER.toString(), CLIENT_ID, jwt -> jwt
                .preferredUsername("userinfo-user")
                .email("userinfo@example.org")
                .addUserGroup("admin")
                .addUserGroup("auditor"));
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
                JsonObject storedUserInfo = OidcCookieStateHandler.create(tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value())
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
    void redirectionEndpointRouteRejectsInvalidEncryptedUserInfo(URI serverUri) {
        userInfoEndpointContentType = "application/jwt";
        OidcTenantConfig tenant = tenantConfigWithUserInfo(serverUri,
                                                           userInfo -> userInfo.jwt(jwt -> jwt
                                                                   .encryptionAlgorithm("RSA-OAEP-256")
                                                                   .contentEncryptionAlgorithm("A256GCM")
                                                                   .decryptionJwk(Resource.create(
                                                                           "oidc-next-encrypt-jwk.json"))));
        String validEncrypted = encryptedUserInfo(SUBJECT,
                                                  EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256,
                                                  EncryptedJwt.SupportedEncryption.A256GCM,
                                                  encryptKeys,
                                                  "encrypt-rsa");
        WebServer rpServer = oidcFeatureServer(providerConfig(tenant));
        try {
            for (String invalidResponse : List.of(
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
                                                                   .decryptionJwk(Resource.create(
                                                                           "oidc-next-encrypt-jwk.json"))));
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
                JsonObject storedUserInfo = OidcCookieStateHandler.create(tenant)
                        .decodeLocalAuthenticationResult(localAuthenticationCookie.value())
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
                assertThat(OidcCookieStateHandler.create(tenant)
                                   .decodeLocalAuthenticationResult(localAuthenticationCookie.value())
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
                assertThat(cookies.size(), is(2));
                assertRemovalCookie(cookies, tenant.cookies().localAuthenticationCookieName());
                assertRemovalCookie(cookies, tenant.cookies().authenticationRequestCookieName());
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
                          .decryptionJwk(Resource.create("oidc-next-encrypt-jwk.json"))));
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
                assertThat(response.as(String.class), is("post_logout_redirect_uri is not allowed"));

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
                assertThat(response.as(String.class), is("post_logout_redirect_uri is not allowed"));
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
                assertThat(response.as(String.class), is("post_logout_redirect_uri is not allowed"));
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
                assertThat(cookies.size(), is(2));
                assertRemovalCookie(cookies, tenant.cookies().localAuthenticationCookieName());
                assertRemovalCookie(cookies, tenant.cookies().authenticationRequestCookieName());
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
                assertThat(response.as(String.class), is("post_logout_redirect_uri is invalid"));
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
                assertThat(response.as(String.class), is("post_logout_redirect_uri is invalid"));
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
                assertThat(response.as(String.class), is("post_logout_redirect_uri is invalid"));
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
                                                                    "shared-cookie-secret",
                                                                    tenantAEndSessionEndpoint,
                                                                    _ -> { });
        OidcTenantConfig tenantB = tenantConfigWithEndSessionLogout("state-b",
                                                                    "auth",
                                                                    "shared-cookie-secret",
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
                                                                    "tenant-a-secret",
                                                                    URI.create("https://issuer.example/logout-a"),
                                                                    _ -> { });
        OidcTenantConfig tenantB = tenantConfigWithEndSessionLogout("state-b",
                                                                    "auth-b",
                                                                    "tenant-b-secret",
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
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfigWithLogout() {
        return tenantConfigWithLogout(_ -> { });
    }

    private static OidcTenantConfig tenantConfigWithLogout(Consumer<OidcLogoutConfig.Builder> logout) {
        return tenantConfigWithLogout("__Host-helidon-oidc-state",
                                      "__Host-helidon-oidc-auth",
                                      COOKIE_SECRET,
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
                                                COOKIE_SECRET,
                                                END_SESSION_ENDPOINT_URI,
                                                endSession,
                                                tenantCustomizer);
    }

    private static OidcTenantConfig tenantConfigWithEndSessionLogout(String authenticationRequestCookieName,
                                                                    String localAuthenticationCookieName,
                                                                    String cookieSecret,
                                                                    URI endSessionEndpointUri,
                                                                    Consumer<OidcEndSessionConfig.Builder> endSession) {
        return tenantConfigWithEndSessionLogout(authenticationRequestCookieName,
                                               localAuthenticationCookieName,
                                               cookieSecret,
                                               endSessionEndpointUri,
                                               endSession,
                                               _ -> { });
    }

    private static OidcTenantConfig tenantConfigWithEndSessionLogout(String authenticationRequestCookieName,
                                                                    String localAuthenticationCookieName,
                                                                    String cookieSecret,
                                                                    URI endSessionEndpointUri,
                                                                    Consumer<OidcEndSessionConfig.Builder> endSession,
                                                                    Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig.Builder builder = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .endSessionEndpointUri(endSessionEndpointUri))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .logout(logout -> logout.endSession(endSession))
                .cookies(it -> it.authenticationRequestCookieName(authenticationRequestCookieName)
                        .localAuthenticationCookieName(localAuthenticationCookieName)
                        .encryptionSecret(cookieSecret));
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
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfigWithLogout(String authenticationRequestCookieName,
                                                          String localAuthenticationCookieName,
                                                          String cookieSecret) {
        return tenantConfigWithLogout(authenticationRequestCookieName,
                                      localAuthenticationCookieName,
                                      cookieSecret,
                                      _ -> { });
    }

    private static OidcTenantConfig tenantConfigWithLogout(String authenticationRequestCookieName,
                                                          String localAuthenticationCookieName,
                                                          String cookieSecret,
                                                          Consumer<OidcLogoutConfig.Builder> logout) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
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
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfigWithUserInfo(URI openIdProviderUri) {
        return tenantConfigWithUserInfo(openIdProviderUri, _ -> { });
    }

    private static OidcTenantConfig tenantConfigWithUserInfo(URI openIdProviderUri,
                                                            Consumer<OidcUserInfoConfig.Builder> userInfo) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(openIdProviderUri.resolve("token"))
                        .userInfoEndpointUri(openIdProviderUri.resolve("userinfo"))
                        .jwksUri(openIdProviderUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .userInfo(userInfo)
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
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
        routing.get("/.well-known/openid-configuration", (request, response) -> {
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

    private static SetCookie authenticationRequestCookie(URI callbackUri, OidcTenantConfig tenant) {
        return authenticationRequestCookie(callbackUri, tenant, URI.create("https://rp.example/resource"));
    }

    private static SetCookie authenticationRequestCookie(URI callbackUri,
                                                        OidcTenantConfig tenant,
                                                        URI originalUri) {
        Instant now = Instant.now();
        return OidcCookieStateHandler.create(tenant)
                .createAuthenticationRequestCookie(new OidcAuthenticationRequestState("default",
                                                                                         STATE,
                                                                                         NONCE,
                                                                                         PKCE_VERIFIER,
                                                                                         ISSUER.toString(),
                                                                                         originalUri,
                                                                                         callbackUri,
                                                                                         now.minusSeconds(1),
                                                                                         now.plusSeconds(60)));
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

    private static String signedUserInfo(String subject,
                                         String issuer,
                                         String audience,
                                         Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder jwt = Jwt.builder()
                .type("JWT")
                .subject(subject)
                .issuer(issuer)
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .addAudience(audience);
        customizer.accept(jwt);
        return SignedJwt.sign(jwt.build(), signKeys.forKeyId("sign-rsa").orElseThrow())
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
