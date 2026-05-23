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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

@ServerTest
@Execution(ExecutionMode.SAME_THREAD)
class OidcRefreshTokenManagerTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI ORIGINAL_URI = URI.create("https://rp.example/resource");
    private static final String AUDIENCE = "api://default";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_SECRET = "client-secret";
    private static final String SUBJECT = "user1-id";
    private static final String USERNAME = "user1";
    private static final String COOKIE_SECRET = "test-cookie-secret";
    private static final String OLD_ACCESS_TOKEN = "old-access-token";
    private static final String OLD_REFRESH_TOKEN = "old-refresh-token";
    private static final String REFRESHED_ACCESS_TOKEN = "refreshed-access-token";
    private static final String ROTATED_REFRESH_TOKEN = "rotated-refresh-token";
    private static final long AUTHENTICATION_TIME = 1_778_869_200L;

    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();
    private static final AtomicReference<RecordedRequest> RECORDED_INTROSPECTION_REQUEST = new AtomicReference<>();
    private static final AtomicReference<String> RECORDED_USER_INFO_AUTHORIZATION = new AtomicReference<>();

    private static JwkKeys signKeys;
    private static String verifyJwkSet;
    private static volatile int responseStatus;
    private static volatile String responseBody;
    private static volatile int introspectionResponseStatus;
    private static volatile String introspectionResponseBody;
    private static volatile int userInfoResponseStatus;
    private static volatile String userInfoResponseBody;

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        verifyJwkSet = Resource.create("oidc-next-verify-jwk.json").string();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.post("/token", OidcRefreshTokenManagerTest::handleTokenEndpoint);
        routing.post("/introspect", OidcRefreshTokenManagerTest::handleIntrospectionEndpoint);
        routing.get("/userinfo", OidcRefreshTokenManagerTest::handleUserInfoEndpoint);
        routing.get("/jwks", (request, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(verifyJwkSet));
    }

    @BeforeEach
    void setUp() {
        responseStatus = 200;
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN).toString();
        introspectionResponseStatus = 200;
        introspectionResponseBody = activeIntrospectionResponse().toString();
        userInfoResponseStatus = 200;
        userInfoResponseBody = userInfoResponse(SUBJECT, "refetched-user").toString();
        RECORDED_REQUEST.set(null);
        RECORDED_INTROSPECTION_REQUEST.set(null);
        RECORDED_USER_INFO_AUTHORIZATION.set(null);
    }

    @Test
    void localAuthenticationRefreshesExpiredAccessTokenAndRotatesRefreshToken(URI serverUri) {
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(), is(SUBJECT));
        assertThat(subject.principal().getName(), is(USERNAME));

        TokenCredential credential = subject.publicCredential(TokenCredential.class).orElseThrow();
        assertThat(credential.token(), is(REFRESHED_ACCESS_TOKEN));
        assertThat(credential.getExpTime().orElseThrow().isAfter(now.plusSeconds(500)), is(true));
        assertThat(subject.grantsByType("scope").stream().map(it -> it.getName()).toList(),
                   is(List.of("openid", "email")));

        List<String> setCookies = response.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase());
        assertThat(setCookies.size(), is(1));
        SetCookie refreshedCookie = SetCookie.parse(setCookies.getFirst());
        OidcLocalAuthenticationResult stored = OidcCookieStateHandler.create(tenant)
                .readLocalAuthenticationResult(refreshedCookie.value(), Instant.now())
                .orElseThrow();
        assertThat(stored.accessToken(), is(REFRESHED_ACCESS_TOKEN));
        assertThat(stored.refreshToken().orElse(""), is(ROTATED_REFRESH_TOKEN));
        assertThat(stored.scope().orElse(""), is("openid email"));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(),
                   is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("refresh_token"),
                                                       "refresh_token", List.of(OLD_REFRESH_TOKEN))));
    }

    @Test
    void localAuthenticationDoesNotRefreshAccessTokenOutsideClockSkew(URI serverUri) {
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.plusSeconds(120));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user()
                           .orElseThrow()
                           .publicCredential(TokenCredential.class)
                           .orElseThrow()
                           .token(),
                   is(OLD_ACCESS_TOKEN));
        assertThat(response.responseHeaders().containsKey(HeaderNames.SET_COOKIE.defaultCase()), is(false));
        assertThat(RECORDED_REQUEST.get(), is(nullValue()));
    }

    @Test
    void localAuthenticationRefreshesAccessTokenWithinClockSkew(URI serverUri) {
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.plusSeconds(30));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user()
                           .orElseThrow()
                           .publicCredential(TokenCredential.class)
                           .orElseThrow()
                           .token(),
                   is(REFRESHED_ACCESS_TOKEN));
        assertThat(RECORDED_REQUEST.get() != null, is(true));
    }

    @Test
    void refreshResponseWithoutRefreshTokenOrScopePreservesStoredValues(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN, null, null, 600).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().grantsByType("scope").stream().map(it -> it.getName()).toList(),
                   is(List.of("openid", "profile")));

        String localAuthenticationCookieName = tenant.cookies().localAuthenticationCookieName();
        SetCookie refreshedCookie = SetCookie.parse(response.responseHeaders()
                                                            .get(HeaderNames.SET_COOKIE.defaultCase())
                                                            .stream()
                                                            .filter(cookie -> cookie.startsWith(
                                                                    localAuthenticationCookieName + "="))
                                                            .findFirst()
                                                            .orElseThrow());
        OidcLocalAuthenticationResult stored = OidcCookieStateHandler.create(tenant)
                .readLocalAuthenticationResult(refreshedCookie.value(), Instant.now())
                .orElseThrow();
        assertThat(stored.accessToken(), is(REFRESHED_ACCESS_TOKEN));
        assertThat(stored.refreshToken().orElse(""), is(OLD_REFRESH_TOKEN));
        assertThat(stored.scope().orElse(""), is("openid profile"));
    }

    @Test
    void invalidGrantClearsLocalAuthenticationAndStartsAuthenticationRequest(URI serverUri) {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid_grant")
                .build()
                .toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.plusSeconds(30));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
        assertThat(RECORDED_REQUEST.get() != null, is(true));
    }

    @Test
    void transientRefreshFailureWithinClockSkewKeepsCurrentAuthentication(URI serverUri) {
        responseStatus = 503;
        responseBody = JsonObject.builder()
                .set("error", "server_error")
                .build()
                .toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.plusSeconds(30));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user()
                           .orElseThrow()
                           .publicCredential(TokenCredential.class)
                           .orElseThrow()
                           .token(),
                   is(OLD_ACCESS_TOKEN));
        assertThat(response.responseHeaders().containsKey(HeaderNames.SET_COOKIE.defaultCase()), is(false));
        assertThat(RECORDED_REQUEST.get() != null, is(true));
    }

    @Test
    void refreshResponseWithoutExpiresInClearsExpiredLocalAuthentication(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN, "openid email", null).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
        assertThat(RECORDED_REQUEST.get() != null, is(true));
    }

    @Test
    void expiredAccessTokenWithoutRefreshTokenStartsAuthenticationRequest(URI serverUri) {
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1),
                                                                        null);

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
        assertThat(RECORDED_REQUEST.get(), is(nullValue()));
    }

    @Test
    void refreshedJwtAccessTokenIsValidatedBeforeCookieIsStored(URI serverUri) {
        String refreshedAccessToken = signedAccessToken(it -> { });
        responseBody = refreshResponse(refreshedAccessToken, ROTATED_REFRESH_TOKEN).toString();
        OidcTenantConfig tenant = tenantWithJwtAccessTokenValidation(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        SetCookie refreshedCookie = SetCookie.parse(response.responseHeaders()
                                                            .get(HeaderNames.SET_COOKIE.defaultCase())
                                                            .getFirst());
        OidcLocalAuthenticationResult stored = OidcCookieStateHandler.create(tenant)
                .readLocalAuthenticationResult(refreshedCookie.value(), Instant.now())
                .orElseThrow();
        assertThat(stored.accessToken(), is(refreshedAccessToken));
    }

    @Test
    void invalidRefreshedAccessTokenClearsLocalAuthentication(URI serverUri) {
        responseBody = refreshResponse(signedAccessToken(it -> it.audience(List.of("api://other"))),
                                       ROTATED_REFRESH_TOKEN).toString();
        OidcTenantConfig tenant = tenantWithJwtAccessTokenValidation(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
    }

    @Test
    void invalidRefreshedAccessTokenWithinClockSkewKeepsCurrentAuthentication(URI serverUri) {
        responseBody = refreshResponse(signedAccessToken(it -> it.audience(List.of("api://other"))),
                                       ROTATED_REFRESH_TOKEN).toString();
        OidcTenantConfig tenant = tenantWithJwtAccessTokenValidation(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.plusSeconds(30));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user()
                           .orElseThrow()
                           .publicCredential(TokenCredential.class)
                           .orElseThrow()
                           .token(),
                   is(OLD_ACCESS_TOKEN));
        assertThat(response.responseHeaders().containsKey(HeaderNames.SET_COOKIE.defaultCase()), is(false));
    }

    @Test
    void refreshedOpaqueAccessTokenIsIntrospectedBeforeCookieIsStored(URI serverUri) {
        OidcTenantConfig tenant = tenantWithIntrospectionAccessTokenValidation(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_INTROSPECTION_REQUEST.get().formParameters(),
                   is(Map.of("token", List.of(REFRESHED_ACCESS_TOKEN),
                             "token_type_hint", List.of("access_token"))));
    }

    @Test
    void inactiveRefreshedOpaqueAccessTokenClearsLocalAuthentication(URI serverUri) {
        introspectionResponseBody = JsonObject.builder()
                .set("active", false)
                .build()
                .toString();
        OidcTenantConfig tenant = tenantWithIntrospectionAccessTokenValidation(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
    }

    @Test
    void refreshedIdTokenReplacesStoredIdToken(URI serverUri) {
        String refreshedIdToken = signedIdToken(it -> it.nonce(null)
                .preferredUsername("refreshed-user"));
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       refreshedIdToken).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().getName(), is("refreshed-user"));
        SetCookie refreshedCookie = SetCookie.parse(response.responseHeaders()
                                                            .get(HeaderNames.SET_COOKIE.defaultCase())
                                                            .getFirst());
        OidcLocalAuthenticationResult stored = OidcCookieStateHandler.create(tenant)
                .readLocalAuthenticationResult(refreshedCookie.value(), Instant.now())
                .orElseThrow();
        assertThat(stored.idToken().rawToken(), is(refreshedIdToken));
    }

    @Test
    void refreshRequeriesUserInfoAndStoresRefreshedUserInfo(URI serverUri) {
        OidcTenantConfig tenant = tenantWithUserInfo(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1),
                                                                        OLD_REFRESH_TOKEN,
                                                                        JsonObject.builder()
                                                                                .set("sub", SUBJECT)
                                                                                .set("preferred_username",
                                                                                     "old-userinfo-user")
                                                                                .build(),
                                                                        it -> { });

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().getName(), is("refetched-user"));
        assertThat(RECORDED_USER_INFO_AUTHORIZATION.get(), is("Bearer " + REFRESHED_ACCESS_TOKEN));
        SetCookie refreshedCookie = SetCookie.parse(response.responseHeaders()
                                                            .get(HeaderNames.SET_COOKIE.defaultCase())
                                                            .getFirst());
        OidcLocalAuthenticationResult stored = OidcCookieStateHandler.create(tenant)
                .readLocalAuthenticationResult(refreshedCookie.value(), Instant.now())
                .orElseThrow();
        assertThat(stored.userInfo().orElseThrow().stringValue("preferred_username").orElse(""),
                   is("refetched-user"));
    }

    @Test
    void invalidRefreshedUserInfoClearsExpiredLocalAuthentication(URI serverUri) {
        userInfoResponseBody = userInfoResponse("other-subject", "refetched-user").toString();
        OidcTenantConfig tenant = tenantWithUserInfo(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1),
                                                                        OLD_REFRESH_TOKEN,
                                                                        JsonObject.builder()
                                                                                .set("sub", SUBJECT)
                                                                                .build(),
                                                                        it -> { });

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
        assertThat(RECORDED_USER_INFO_AUTHORIZATION.get(), is("Bearer " + REFRESHED_ACCESS_TOKEN));
    }

    @Test
    void refreshedIdTokenShorterExpirationShortensLocalAuthentication(URI serverUri) {
        Instant now = Instant.now();
        Instant refreshedExpiration = now.plusSeconds(120).truncatedTo(ChronoUnit.SECONDS);
        String refreshedIdToken = signedIdToken(it -> it.nonce(null)
                .expirationTime(refreshedExpiration));
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       refreshedIdToken).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        SetCookie refreshedCookie = SetCookie.parse(response.responseHeaders()
                                                            .get(HeaderNames.SET_COOKIE.defaultCase())
                                                            .getFirst());
        OidcLocalAuthenticationResult stored = OidcCookieStateHandler.create(tenant)
                .readLocalAuthenticationResult(refreshedCookie.value(), Instant.now())
                .orElseThrow();
        assertThat(stored.expiresAt(), is(refreshedExpiration));
    }

    @Test
    void refreshedIdTokenWithMatchingNonceAndAuthenticationTimeIsAccepted(URI serverUri) {
        String refreshedIdToken = signedIdToken(it -> it.addPayloadClaim("auth_time", AUTHENTICATION_TIME));
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       refreshedIdToken).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1),
                                                                        OLD_REFRESH_TOKEN,
                                                                        it -> it.addPayloadClaim("auth_time",
                                                                                                  AUTHENTICATION_TIME));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void changedNonceInRefreshedIdTokenClearsExpiredLocalAuthentication(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       signedIdToken(it -> it.nonce("other-nonce"))).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
    }

    @Test
    void changedAuthenticationTimeInRefreshedIdTokenClearsExpiredLocalAuthentication(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       signedIdToken(it -> it.nonce(null)
                                               .addPayloadClaim("auth_time",
                                                                AUTHENTICATION_TIME + 60))).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1),
                                                                        OLD_REFRESH_TOKEN,
                                                                        it -> it.addPayloadClaim("auth_time",
                                                                                                  AUTHENTICATION_TIME));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
    }

    @Test
    void changedAuthorizedPartyInRefreshedIdTokenClearsExpiredLocalAuthentication(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       signedIdToken(it -> it.nonce(null))).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1),
                                                                        OLD_REFRESH_TOKEN,
                                                                        it -> it.addPayloadClaim("azp", CLIENT_ID));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
    }

    @Test
    void invalidRefreshedIdTokenWithinClockSkewKeepsCurrentAuthentication(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       signedIdToken(it -> it.nonce(null)
                                               .subject("other-user-id"))).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.plusSeconds(30));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user()
                           .orElseThrow()
                           .publicCredential(TokenCredential.class)
                           .orElseThrow()
                           .token(),
                   is(OLD_ACCESS_TOKEN));
        assertThat(response.responseHeaders().containsKey(HeaderNames.SET_COOKIE.defaultCase()), is(false));
    }

    @Test
    void changedSubjectInRefreshedIdTokenClearsLocalAuthentication(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       signedIdToken(it -> it.nonce(null)
                                               .subject("other-user-id"))).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
    }

    @Test
    void changedIssuerInRefreshedIdTokenClearsLocalAuthentication(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       signedIdToken(it -> it.nonce(null)
                                               .issuer("https://other.example"))).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
    }

    @Test
    void changedAudienceInRefreshedIdTokenClearsLocalAuthentication(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN,
                                       ROTATED_REFRESH_TOKEN,
                                       "openid email",
                                       600,
                                       signedIdToken(it -> it.nonce(null)
                                               .addAudience("other-audience")
                                               .addPayloadClaim("azp", CLIENT_ID))).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
    }

    private static void handleTokenEndpoint(ServerRequest request, ServerResponse response) {
        RECORDED_REQUEST.set(new RecordedRequest(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""),
                                                formParameters(request.content().as(Parameters.class))));
        response.status(responseStatus)
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .send(responseBody);
    }

    private static void handleIntrospectionEndpoint(ServerRequest request, ServerResponse response) {
        RECORDED_INTROSPECTION_REQUEST.set(
                new RecordedRequest(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""),
                                    formParameters(request.content().as(Parameters.class))));
        response.status(introspectionResponseStatus)
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .send(introspectionResponseBody);
    }

    private static void handleUserInfoEndpoint(ServerRequest request, ServerResponse response) {
        RECORDED_USER_INFO_AUTHORIZATION.set(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""));
        response.status(userInfoResponseStatus)
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .send(userInfoResponseBody);
    }

    private static OidcTenantConfig tenant(URI serverUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(serverUri.resolve("token"))
                        .jwksUri(serverUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantWithJwtAccessTokenValidation(URI serverUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(serverUri.resolve("token"))
                        .jwksUri(serverUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .protectedResource(it -> it.enabled(false)
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantWithIntrospectionAccessTokenValidation(URI serverUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(serverUri.resolve("token"))
                        .introspectionEndpointUri(serverUri.resolve("introspect"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .protectedResource(it -> it.enabled(false)
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience(AUDIENCE)))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantWithUserInfo(URI serverUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(serverUri.resolve("token"))
                        .userInfoEndpointUri(serverUri.resolve("userinfo"))
                        .jwksUri(serverUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .userInfo(it -> { })
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static AuthenticationResponse authenticate(OidcTenantConfig tenant, SetCookie localAuthenticationCookie) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .buildPrototype())
                .authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .header(HeaderNames.COOKIE.defaultCase(),
                                localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                        .build()));
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant,
                                                       Instant createdAt,
                                                       Instant expiresAt,
                                                       Instant accessTokenExpiresAt) {
        return localAuthenticationCookie(tenant, createdAt, expiresAt, accessTokenExpiresAt, OLD_REFRESH_TOKEN);
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant,
                                                       Instant createdAt,
                                                       Instant expiresAt,
                                                       Instant accessTokenExpiresAt,
                                                       String refreshToken) {
        return localAuthenticationCookie(tenant,
                                         createdAt,
                                         expiresAt,
                                         accessTokenExpiresAt,
                                         refreshToken,
                                         it -> { });
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant,
                                                       Instant createdAt,
                                                       Instant expiresAt,
                                                       Instant accessTokenExpiresAt,
                                                       String refreshToken,
                                                       Consumer<Jwt.Builder> idTokenCustomizer) {
        return localAuthenticationCookie(tenant,
                                         createdAt,
                                         expiresAt,
                                         accessTokenExpiresAt,
                                         refreshToken,
                                         null,
                                         idTokenCustomizer);
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant,
                                                       Instant createdAt,
                                                       Instant expiresAt,
                                                       Instant accessTokenExpiresAt,
                                                       String refreshToken,
                                                       JsonObject userInfo,
                                                       Consumer<Jwt.Builder> idTokenCustomizer) {
        String idToken = signedIdToken(idTokenCustomizer);
        SignedJwt signedJwt = SignedJwt.parseToken(idToken);
        return OidcCookieStateHandler.create(tenant)
                .createLocalAuthenticationResultCookie(OidcLocalAuthenticationResult.create(
                        "default",
                        OidcValidatedIdToken.create(idToken, signedJwt, signedJwt.getJwt()),
                        OLD_ACCESS_TOKEN,
                        "Bearer",
                        refreshToken,
                        "openid profile",
                        userInfo,
                        createdAt,
                        expiresAt,
                        accessTokenExpiresAt));
    }

    private static String signedIdToken(Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(ISSUER.toString())
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issueTime(now)
                .expirationTime(now.plusSeconds(3600))
                .addAudience(CLIENT_ID)
                .nonce("nonce")
                .preferredUsername(USERNAME);
        customizer.accept(builder);
        return SignedJwt.sign(builder.build(), signKeys.forKeyId("sign-rsa").orElseThrow())
                .tokenContent();
    }

    private static String signedAccessToken(Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.builder()
                .type("at+jwt")
                .subject(SUBJECT)
                .preferredUsername(USERNAME)
                .issuer(ISSUER.toString())
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .addAudience(AUDIENCE);
        customizer.accept(builder);
        return SignedJwt.sign(builder.build(), signKeys.forKeyId("sign-rsa").orElseThrow())
                .tokenContent();
    }

    private static JsonObject refreshResponse(String accessToken, String refreshToken) {
        return refreshResponse(accessToken, refreshToken, "openid email", 600);
    }

    private static JsonObject refreshResponse(String accessToken,
                                              String refreshToken,
                                              String scope,
                                              Integer expiresIn) {
        return refreshResponse(accessToken, refreshToken, scope, expiresIn, null);
    }

    private static JsonObject refreshResponse(String accessToken,
                                              String refreshToken,
                                              String scope,
                                              Integer expiresIn,
                                              String idToken) {
        JsonObject.Builder builder = JsonObject.builder()
                .set("access_token", accessToken)
                .set("token_type", "Bearer");
        if (refreshToken != null) {
            builder.set("refresh_token", refreshToken);
        }
        if (expiresIn != null) {
            builder.set("expires_in", expiresIn);
        }
        if (scope != null) {
            builder.set("scope", scope);
        }
        if (idToken != null) {
            builder.set("id_token", idToken);
        }
        return builder.build();
    }

    private static JsonObject activeIntrospectionResponse() {
        Instant now = Instant.now();
        return JsonObject.builder()
                .set("active", true)
                .set("sub", SUBJECT)
                .set("preferred_username", USERNAME)
                .set("iss", ISSUER.toString())
                .setStrings("aud", List.of(AUDIENCE))
                .set("exp", now.plus(1, ChronoUnit.HOURS).getEpochSecond())
                .set("iat", now.minus(1, ChronoUnit.MINUTES).getEpochSecond())
                .set("token_type", "Bearer")
                .build();
    }

    private static JsonObject userInfoResponse(String subject, String username) {
        return JsonObject.builder()
                .set("sub", subject)
                .set("preferred_username", username)
                .build();
    }

    private static void assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(AuthenticationResponse response,
                                                                                       OidcTenantConfig tenant) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
        assertThat(response.statusCode().orElse(-1), is(303));
        assertThat(response.responseHeaders().get(HeaderNames.LOCATION.defaultCase()).getFirst(),
                   containsString("/authorize"));

        List<String> setCookies = response.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase());
        assertThat(setCookies.stream()
                           .anyMatch(cookie -> cookie.startsWith(tenant.cookies()
                                                                         .authenticationRequestCookieName()
                                                                 + "=")),
                   is(true));
        assertThat(setCookies.stream()
                           .anyMatch(cookie -> cookie.startsWith(tenant.cookies()
                                                                         .localAuthenticationCookieName()
                                                                 + "=")
                                   && cookie.contains("Expires=")),
                   is(true));
    }

    private static Map<String, List<String>> formParameters(Parameters parameters) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (String name : parameters.names()) {
            result.put(name, parameters.all(name));
        }
        return result;
    }

    private record RecordedRequest(String authorization, Map<String, List<String>> formParameters) {
    }
}
