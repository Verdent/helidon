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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.SecurityTime;
import io.helidon.security.Subject;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
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
import static org.hamcrest.CoreMatchers.notNullValue;
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
    private static final String COOKIE_PASSWORD = "test-cookie-password";
    private static final String OLD_ACCESS_TOKEN = "old-access-token";
    private static final String OLD_REFRESH_TOKEN = "old-refresh-token";
    private static final String REFRESHED_ACCESS_TOKEN = "refreshed-access-token";
    private static final String ROTATED_REFRESH_TOKEN = "rotated-refresh-token";
    private static final long AUTHENTICATION_TIME = 1_778_869_200L;

    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();
    private static final AtomicReference<RecordedRequest> RECORDED_INTROSPECTION_REQUEST = new AtomicReference<>();
    private static final AtomicReference<String> RECORDED_USER_INFO_AUTHORIZATION = new AtomicReference<>();
    private static final AtomicInteger TOKEN_REQUEST_COUNT = new AtomicInteger();
    private static final AtomicReference<TokenEndpointResponder> TOKEN_ENDPOINT_RESPONDER = new AtomicReference<>();

    private static JwkKeys signKeys;
    private static JwkKeys encryptKeys;
    private static String verifyJwkSet;
    private static volatile int responseStatus;
    private static volatile String responseBody;
    private static volatile int introspectionResponseStatus;
    private static volatile String introspectionResponseBody;
    private static volatile int userInfoResponseStatus;
    private static volatile String userInfoResponseContentType;
    private static volatile String userInfoResponseBody;

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        encryptKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-encrypt-jwk.json"))
                .build();
        verifyJwkSet = Resource.create("oidc-next-verify-public-jwk.json").string();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.post("/token", OidcRefreshTokenManagerTest::handleTokenEndpoint);
        routing.post("/introspect", OidcRefreshTokenManagerTest::handleIntrospectionEndpoint);
        routing.get("/userinfo", OidcRefreshTokenManagerTest::handleUserInfoEndpoint);
        routing.get("/jwks", (_, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(verifyJwkSet));
    }

    @BeforeEach
    void setUp() {
        responseStatus = 200;
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN).toString();
        introspectionResponseStatus = 200;
        introspectionResponseBody = activeIntrospectionResponse().toString();
        userInfoResponseStatus = 200;
        userInfoResponseContentType = "application/json";
        userInfoResponseBody = userInfoResponse(SUBJECT, "refetched-user").toString();
        RECORDED_REQUEST.set(null);
        RECORDED_INTROSPECTION_REQUEST.set(null);
        RECORDED_USER_INFO_AUTHORIZATION.set(null);
        TOKEN_REQUEST_COUNT.set(0);
        TOKEN_ENDPOINT_RESPONDER.set(null);
    }

    @Test
    void concurrentVirtualThreadRequestsShareOneRotatingRefresh(URI serverUri) throws Exception {
        int taskCount = 16;
        CountDownLatch tasksReady = new CountDownLatch(taskCount);
        CountDownLatch startTasks = new CountDownLatch(1);
        CountDownLatch firstRequestStarted = new CountDownLatch(1);
        CountDownLatch secondRequestStarted = new CountDownLatch(1);
        CountDownLatch releaseFirstRequest = new CountDownLatch(1);
        String refreshedAccessToken = "a".repeat(6000);
        String successfulResponse = refreshResponse(refreshedAccessToken, ROTATED_REFRESH_TOKEN).toString();
        String invalidGrantResponse = JsonObject.builder().set("error", "invalid_grant").build().toString();
        TOKEN_ENDPOINT_RESPONDER.set((requestNumber, response) -> {
            if (requestNumber == 1) {
                firstRequestStarted.countDown();
                await(releaseFirstRequest);
                sendTokenResponse(response, 200, successfulResponse);
            } else {
                secondRequestStarted.countDown();
                sendTokenResponse(response, 400, invalidGrantResponse);
            }
        });
        OidcTenantConfig tenant = tenant(serverUri);
        OidcProvider provider = provider(tenant);
        OidcCookieStateHandler cookieStateHandler = OidcCookieStateHandler.create("default", tenant);
        Instant now = Instant.now();
        LocalAuthenticationCookies cookies = localAuthenticationCookies(tenant,
                                                                         now.minusSeconds(60),
                                                                         now.plusSeconds(3600),
                                                                         now.minusSeconds(1));

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<AuthenticationResponse>> responses = new ArrayList<>(taskCount);
            for (int i = 0; i < taskCount; i++) {
                responses.add(executor.submit(() -> {
                    tasksReady.countDown();
                    if (!startTasks.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to start refresh task");
                    }
                    return authenticate(provider, cookies);
                }));
            }
            assertThat(tasksReady.await(5, TimeUnit.SECONDS), is(true));
            startTasks.countDown();
            assertThat(firstRequestStarted.await(5, TimeUnit.SECONDS), is(true));
            boolean duplicateRefreshStarted;
            try {
                duplicateRefreshStarted = secondRequestStarted.await(500, TimeUnit.MILLISECONDS);
            } finally {
                releaseFirstRequest.countDown();
            }

            List<String> sharedChunkValues = null;
            for (Future<AuthenticationResponse> responseFuture : responses) {
                AuthenticationResponse response = responseFuture.get(5, TimeUnit.SECONDS);
                assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                List<String> values = response.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase()).stream()
                        .map(SetCookie::parse).map(SetCookie::value).toList();
                assertThat(values.size() > 1, is(true));
                if (sharedChunkValues == null) {
                    sharedChunkValues = values;
                }
                assertThat(values, is(sharedChunkValues));
                OidcLocalAuthenticationResult result = storedLocalAuthenticationResult(response,
                                                                                        tenant,
                                                                                        cookieStateHandler);
                assertThat(result.accessToken(), is(refreshedAccessToken));
                assertThat(result.refreshToken().orElse(""), is(ROTATED_REFRESH_TOKEN));
                assertThat(result.browserSessionGeneration(), is(Optional.of(cookies.generation())));
            }
            assertThat(duplicateRefreshStarted, is(false));
        } finally {
            releaseFirstRequest.countDown();
        }

        assertThat(TOKEN_REQUEST_COUNT.get(), is(1));
    }

    @Test
    void completedRefreshIsSharedWithLateRequestUsingSourceCookie(URI serverUri) {
        String successfulResponse = refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN).toString();
        String invalidGrantResponse = JsonObject.builder().set("error", "invalid_grant").build().toString();
        TOKEN_ENDPOINT_RESPONDER.set((requestNumber, response) -> sendTokenResponse(
                response,
                requestNumber == 1 ? 200 : 400,
                requestNumber == 1 ? successfulResponse : invalidGrantResponse));
        OidcTenantConfig tenant = tenant(serverUri);
        OidcProvider provider = provider(tenant);
        Instant now = Instant.now();
        SetCookie sourceCookie = localAuthenticationCookie(tenant,
                                                           now.minusSeconds(60),
                                                           now.plusSeconds(3600),
                                                           now.minusSeconds(1));

        AuthenticationResponse first = authenticate(provider, sourceCookie);
        AuthenticationResponse late = authenticate(provider, sourceCookie);

        assertThat(first.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(late.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(storedLocalAuthenticationResult(first, tenant).refreshToken().orElse(""),
                   is(ROTATED_REFRESH_TOKEN));
        assertThat(storedLocalAuthenticationResult(late, tenant).refreshToken().orElse(""),
                   is(ROTATED_REFRESH_TOKEN));
        assertThat(TOKEN_REQUEST_COUNT.get(), is(1));
    }

    @Test
    void refreshCapacityRejectionDoesNotMutateCookiesAndNeverAuthenticatesExpiredToken(URI serverUri) throws Exception {
        CountDownLatch leaderStarted = new CountDownLatch(1);
        CountDownLatch releaseLeader = new CountDownLatch(1);
        TOKEN_ENDPOINT_RESPONDER.set((_, response) -> {
            leaderStarted.countDown();
            await(releaseLeader);
            sendTokenResponse(response,
                              200,
                              refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN).toString());
        });
        OidcTenantConfig tenant = tenant(
                serverUri,
                List.of(),
                authorizationCode -> authorizationCode.refreshRemoteWork(remoteWork -> remoteWork
                        .maxConcurrent(1)
                        .maxQueued(0)
                        .admissionTimeout(Duration.ofHours(1))));
        OidcProvider provider = provider(tenant);
        Instant now = Instant.now();
        SetCookie leaderCookie = localAuthenticationCookie(tenant,
                                                           now.minusSeconds(60),
                                                           now.plusSeconds(3600),
                                                           now.minusSeconds(1));
        SetCookie expiredRejectedCookie = localAuthenticationCookie(tenant,
                                                                    now.minusSeconds(59),
                                                                    now.plusSeconds(3600),
                                                                    now.minusSeconds(1),
                                                                    "expired-rejected-refresh-token");
        SetCookie validRejectedCookie = localAuthenticationCookie(tenant,
                                                                  now.minusSeconds(58),
                                                                  now.plusSeconds(3600),
                                                                  now.plusSeconds(30),
                                                                  "valid-rejected-refresh-token");

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<AuthenticationResponse> leader = executor.submit(() -> authenticate(provider, leaderCookie));
            assertThat(leaderStarted.await(5, TimeUnit.SECONDS), is(true));

            AuthenticationResponse expiredRejected = authenticate(provider, expiredRejectedCookie);
            AuthenticationResponse validRejected = authenticate(provider, validRejectedCookie);

            assertThat(expiredRejected.status(), is(SecurityResponse.SecurityStatus.FAILURE));
            assertThat(expiredRejected.statusCode().orElse(-1), is(503));
            assertThat(expiredRejected.description().orElse(""), is("OIDC authentication is unavailable"));
            assertThat(expiredRejected.responseHeaders().containsKey(HeaderNames.SET_COOKIE.defaultCase()), is(false));
            assertThat(validRejected.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertAccessToken(validRejected, OLD_ACCESS_TOKEN);
            assertThat(validRejected.responseHeaders().containsKey(HeaderNames.SET_COOKIE.defaultCase()), is(false));
            assertThat(TOKEN_REQUEST_COUNT.get(), is(1));

            releaseLeader.countDown();
            assertThat(leader.get(5, TimeUnit.SECONDS).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        } finally {
            releaseLeader.countDown();
        }
    }

    @Test
    void cachedTransientFailureCannotAuthenticateSourceTokenAfterItExpires(URI serverUri) {
        responseStatus = 503;
        responseBody = JsonObject.builder().set("error", "server_error").build().toString();
        OidcTenantConfig tenant = tenant(serverUri);
        OidcProvider provider = provider(tenant);
        Instant now = Instant.now();
        SetCookie sourceCookie = localAuthenticationCookie(tenant,
                                                           now.minusSeconds(60),
                                                           now.plusSeconds(3600),
                                                           now.plusSeconds(30));

        AuthenticationResponse beforeExpiration = authenticate(provider, sourceCookie);
        AuthenticationResponse afterExpiration = authenticate(provider,
                                                               sourceCookie,
                                                               SecurityTime.builder()
                                                                       .shiftBySeconds(120)
                                                                       .build());

        assertThat(beforeExpiration.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertAccessToken(beforeExpiration, OLD_ACCESS_TOKEN);
        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(afterExpiration, tenant);
        assertThat(TOKEN_REQUEST_COUNT.get(), is(2));
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
        assertThat(subject.principal().id(), is(issuerSubjectPrincipalId()));
        assertThat(subject.principal().getName(), is(USERNAME));

        TokenCredential credential = subject.publicCredential(TokenCredential.class).orElseThrow();
        assertThat(credential.token(), is(REFRESHED_ACCESS_TOKEN));
        assertThat(credential.getExpTime().orElseThrow().isAfter(now.plusSeconds(500)), is(true));
        assertThat(subject.grantsByType("scope").stream().map(it -> it.getName()).toList(),
                   is(List.of("openid", "email")));

        OidcLocalAuthenticationResult stored = storedLocalAuthenticationResult(response, tenant);
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
    void localAuthenticationRefreshSendsConfiguredResources(URI serverUri) {
        OidcTenantConfig tenant = tenantWithAuthorizationCodeResources(serverUri);
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.formParameters().get("resource"),
                   is(List.of("https://api.example.com", "urn:example:contacts")));
    }

    @Test
    void unusableRefreshLifetimesClearExpiredAuthenticationBeforeUserInfo(URI serverUri) {
        int expectedRequests = 0;
        for (String lifetime : List.of("0", "-1", "1.5", "9223372036854775808")) {
            responseBody = JsonObject.builder()
                    .from(refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN, null, null))
                    .set("expires_in", new BigDecimal(lifetime))
                    .build()
                    .toString();
            OidcTenantConfig tenant = tenantWithUserInfo(serverUri);
            Instant now = Instant.now();
            SetCookie cookie = localAuthenticationCookie(tenant,
                                                         now.minusSeconds(60),
                                                         now.plusSeconds(3600),
                                                         now.minusSeconds(1));

            AuthenticationResponse response = authenticate(tenant, cookie);

            assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(response, tenant);
            assertThat(RECORDED_USER_INFO_AUTHORIZATION.get(), is(nullValue()));
            assertThat(TOKEN_REQUEST_COUNT.get(), is(++expectedRequests));
        }
    }

    @Test
    void expiredRefreshResponseKeepsOnlyStillValidSourceToken(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN, null, 0).toString();
        OidcTenantConfig tenant = tenantWithUserInfo(serverUri);
        OidcProvider provider = provider(tenant);
        Instant now = Instant.now();
        SetCookie cookie = localAuthenticationCookie(tenant,
                                                     now.minusSeconds(60),
                                                     now.plusSeconds(3600),
                                                     now.plusSeconds(30));

        AuthenticationResponse response = authenticate(provider, cookie);
        AuthenticationResponse afterExpiration = authenticate(provider,
                                                               cookie,
                                                               SecurityTime.builder().shiftBySeconds(120).build());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertAccessToken(response, OLD_ACCESS_TOKEN);
        assertThat(response.responseHeaders().containsKey(HeaderNames.SET_COOKIE.defaultCase()), is(false));
        assertAuthenticationRequestStartedAndLocalAuthenticationRemoved(afterExpiration, tenant);
        assertThat(RECORDED_USER_INFO_AUTHORIZATION.get(), is(nullValue()));
        assertThat(TOKEN_REQUEST_COUNT.get(), is(2));
    }

    @Test
    void refreshPreservesShortPositiveLifetimes(URI serverUri) {
        int expectedRequests = 0;
        for (int lifetime : List.of(1, 60)) {
            responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN, null, lifetime).toString();
            OidcTenantConfig tenant = tenant(serverUri);
            Instant now = Instant.now();
            SetCookie cookie = localAuthenticationCookie(tenant,
                                                         now.minusSeconds(60),
                                                         now.plusSeconds(3600),
                                                         now.minusSeconds(1));

            AuthenticationResponse response = authenticate(tenant, cookie);

            assertThat("expires_in=" + lifetime, response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertAccessToken(response, REFRESHED_ACCESS_TOKEN);
            OidcLocalAuthenticationResult stored = storedLocalAuthenticationResult(response, tenant);
            assertThat(stored.accessTokenExpiresAt().orElseThrow(), is(stored.createdAt().plusSeconds(lifetime)));
            assertThat(stored.refreshToken().orElseThrow(), is(ROTATED_REFRESH_TOKEN));
            assertThat(TOKEN_REQUEST_COUNT.get(), is(++expectedRequests));
        }
    }

    @Test
    void refreshAcceptsVeryLargeLifetimeWithoutExtendingLocalSession(URI serverUri) {
        responseBody = JsonObject.builder()
                .from(refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN, null, null))
                .set("expires_in", Long.MAX_VALUE)
                .build()
                .toString();
        OidcTenantConfig tenant = tenant(serverUri);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant sessionExpiresAt = now.plusSeconds(3600);
        SetCookie cookie = localAuthenticationCookie(tenant,
                                                     now.minusSeconds(60),
                                                     sessionExpiresAt,
                                                     now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, cookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertAccessToken(response, REFRESHED_ACCESS_TOKEN);
        OidcLocalAuthenticationResult stored = storedLocalAuthenticationResult(response, tenant);
        assertThat(stored.accessTokenExpiresAt().orElseThrow(), is(Instant.MAX));
        assertThat(stored.expiresAt(), is(sessionExpiresAt));
        assertThat(stored.refreshToken().orElseThrow(), is(ROTATED_REFRESH_TOKEN));
        assertThat(TOKEN_REQUEST_COUNT.get(), is(1));
    }

    @Test
    void lateChunkedRefreshCannotRestoreTheBrowserSessionAfterLogout(URI serverUri) throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        String successful = refreshResponse("a".repeat(6000), ROTATED_REFRESH_TOKEN).toString();
        TOKEN_ENDPOINT_RESPONDER.set((_, response) -> {
            started.countDown();
            await(release);
            sendTokenResponse(response, 200, successful);
        });
        OidcTenantConfig tenant = OidcTenantConfig.builder(tenant(serverUri)).logout(OidcLogoutConfig.create()).buildPrototype();
        OidcProviderConfig config = OidcProviderConfig.builder().putTenant("default", tenant).buildPrototype();
        OidcProvider provider = OidcProvider.create(config);
        WebServer rp = WebServer.builder().port(0).routing(routing -> OidcFeature.create(provider).setup(routing)).build().start();
        URI rpUri = URI.create("http://localhost:" + rp.port());
        WebClient client = WebClient.builder().baseUri(rpUri).build();
        Instant now = Instant.now();
        LocalAuthenticationCookies source = localAuthenticationCookies(tenant, now.minusSeconds(60),
                                                                        now.plusSeconds(3600), now.minusSeconds(1));
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<AuthenticationResponse> pending = executor.submit(() -> authenticate(provider, source));
            try {
                assertThat(started.await(5, TimeUnit.SECONDS), is(true));
                SetCookie newGeneration;
                String sourceHeader = source.localAuthentication().name() + "=" + source.localAuthentication().value()
                        + "; " + source.generationCookie().name() + "=" + source.generationCookie().value();
                try (HttpClientResponse logout = client.post("/oidc/logout")
                        .header(HeaderNames.ORIGIN, rpUri.toString()).header(HeaderNames.COOKIE, sourceHeader).request()) {
                    assertThat(logout.status(), is(Status.NO_CONTENT_204));
                    List<SetCookie> cookies = logout.headers().get(HeaderNames.SET_COOKIE).allValues().stream()
                            .map(SetCookie::parse).toList();
                    assertThat(cookies.size(), is(18));
                    newGeneration = cookies.stream().filter(cookie -> cookie.name().endsWith("-generation"))
                            .findFirst().orElseThrow();
                }
                release.countDown();
                AuthenticationResponse late = pending.get(5, TimeUnit.SECONDS);
                assertThat(late.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                List<SetCookie> lateCookies = late.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase()).stream()
                        .map(SetCookie::parse).toList();
                assertThat(lateCookies.size() > 1, is(true));
                assertThat(storedLocalAuthenticationResult(late, tenant).browserSessionGeneration(),
                           is(Optional.of(source.generation())));
                String afterLogout = String.join("; ", lateCookies.stream()
                        .map(cookie -> cookie.name() + "=" + cookie.value()).toList())
                        + "; " + newGeneration.name() + "=" + newGeneration.value();
                AuthenticationResponse result = provider.authenticate(OidcProviderTest.request(null,
                        SecurityEnvironment.builder().targetUri(ORIGINAL_URI)
                                .header(HeaderNames.COOKIE.defaultCase(), afterLogout).build()));
                assertThat(result.status() == SecurityResponse.SecurityStatus.SUCCESS, is(false));
                assertThat(result.user().isEmpty(), is(true));
                assertThat(TOKEN_REQUEST_COUNT.get(), is(1));
            } finally {
                release.countDown();
            }
        } finally {
            client.closeResource();
            try {
                rp.stop();
            } finally {
                provider.close();
            }
        }
    }

    @Test
    void oversizedRotatedSessionFailsWithoutRedeemingTheSourceAgain(URI serverUri) {
        responseBody = refreshResponse(REFRESHED_ACCESS_TOKEN, "r".repeat(24000)).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        OidcProvider provider = provider(tenant);
        Instant now = Instant.now();
        SetCookie source = localAuthenticationCookie(tenant, now.minusSeconds(60), now.plusSeconds(3600), now.minusSeconds(1));

        for (int i = 0; i < 2; i++) {
            AuthenticationResponse response = authenticate(provider, source);
            assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
            assertThat(response.statusCode().orElseThrow(), is(503));
            assertThat(response.user().isEmpty(), is(true));
            List<String> cleared = response.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase());
            assertThat(cleared.size(), is(16));
            cleared.stream().map(SetCookie::parse).forEach(cookie -> {
                assertThat(cookie.value(), is(""));
                assertThat(cookie.expires().orElseThrow().toInstant(), is(Instant.EPOCH));
            });
        }
        assertThat(TOKEN_REQUEST_COUNT.get(), is(1));
    }

    @Test
    void refreshedSessionShrinksAndRemovesObsoleteChunks(URI serverUri) {
        responseBody = refreshResponse("a".repeat(6000), ROTATED_REFRESH_TOKEN).toString();
        OidcTenantConfig tenant = tenant(serverUri);
        OidcProvider provider = provider(tenant);
        Instant now = Instant.now();
        SetCookie source = localAuthenticationCookie(tenant, now.minusSeconds(60), now.plusSeconds(3600), now.minusSeconds(1));
        AuthenticationResponse first = authenticate(provider, source);
        assertThat(first.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        List<SetCookie> largeCookies = first.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase()).stream()
                .map(SetCookie::parse).toList();
        assertThat(largeCookies.size() > 1, is(true));
        String header = String.join("; ", largeCookies.stream().map(cookie -> cookie.name() + "=" + cookie.value()).toList());
        responseBody = refreshResponse("small-token", "next-refresh-token").toString();

        AuthenticationResponse second = provider.authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                .targetUri(ORIGINAL_URI).time(SecurityTime.builder().shiftBySeconds(700).build())
                .header(HeaderNames.COOKIE.defaultCase(), header).build()));

        assertThat(second.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertAccessToken(second, "small-token");
        List<SetCookie> update = second.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase()).stream()
                .map(SetCookie::parse).toList();
        assertThat(update.size(), is(largeCookies.size()));
        assertThat(update.getFirst().value().isEmpty(), is(false));
        update.subList(1, update.size()).forEach(cookie -> {
            assertThat(cookie.value(), is(""));
            assertThat(cookie.expires().orElseThrow().toInstant(), is(Instant.EPOCH));
        });
        assertThat(RECORDED_REQUEST.get().formParameters().get("refresh_token"), is(List.of(ROTATED_REFRESH_TOKEN)));
        assertThat(TOKEN_REQUEST_COUNT.get(), is(2));
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
        assertAccessToken(response, OLD_ACCESS_TOKEN);
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
        assertAccessToken(response, REFRESHED_ACCESS_TOKEN);
        assertThat(RECORDED_REQUEST.get(), is(notNullValue()));
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

        OidcLocalAuthenticationResult stored = storedLocalAuthenticationResult(response, tenant);
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
        assertThat(RECORDED_REQUEST.get(), is(notNullValue()));
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
        assertAccessToken(response, OLD_ACCESS_TOKEN);
        assertThat(response.responseHeaders().containsKey(HeaderNames.SET_COOKIE.defaultCase()), is(false));
        assertThat(RECORDED_REQUEST.get(), is(notNullValue()));
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
        assertThat(RECORDED_REQUEST.get(), is(notNullValue()));
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
    void jwksOverloadAfterSuccessfulRefreshClearsTheSessionAndDoesNotRedeemTheSourceAgain(URI serverUri) throws Exception {
        for (String validation : List.of("id-token", "user-info")) {
            for (boolean expired : List.of(false, true)) {
                TOKEN_REQUEST_COUNT.set(0);
                CountDownLatch entered = new CountDownLatch(1);
                CountDownLatch release = new CountDownLatch(1);
                WebServer keys = WebServer.builder().port(0).routing(routing -> routing.get("/jwks", (_, response) -> {
                    entered.countDown();
                    await(release);
                    response.header(HeaderValues.CONTENT_TYPE_JSON).send(verifyJwkSet);
                })).build().start();
                OidcTenantConfig base = "user-info".equals(validation)
                        ? tenantWithUserInfo(serverUri, info -> info.jwt(jwt -> jwt.signingAlgorithm("RS256")))
                        : tenant(serverUri);
                OidcTenantConfig tenant = OidcTenantConfig.builder(base)
                        .endpoints(OidcEndpointConfig.builder(base.endpoints())
                                           .jwksUri(URI.create("http://localhost:" + keys.port() + "/jwks")).buildPrototype())
                        .jwkSet(jwkSet -> jwkSet.maxQueued(0)).buildPrototype();
                responseBody = "id-token".equals(validation)
                        ? refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN, "openid profile", 600,
                                          signedIdToken(token -> token.nonce(null))).toString()
                        : refreshResponse(REFRESHED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN).toString();
                if ("user-info".equals(validation)) {
                    userInfoResponseContentType = "application/jwt";
                    userInfoResponseBody = SignedJwt.sign(Jwt.builder().algorithm("RS256").keyId("verify-rsa")
                                                                  .issuer(ISSUER.toString()).subject(SUBJECT)
                                                                  .addAudience(CLIENT_ID).build(),
                                                          signKeys.forKeyId("sign-rsa").orElseThrow()).tokenContent();
                }
                try (OidcProvider provider = provider(tenant);
                     ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                    OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("default").orElseThrow();
                    assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                               context.ready(), is(true));
                    Future<?> load = executor.submit(() -> context.jwkSetManager().jwkKeys());
                    try {
                        assertThat(entered.await(5, TimeUnit.SECONDS), is(true));
                        Instant now = Instant.now();
                        SetCookie source = localAuthenticationCookie(tenant, now.minusSeconds(60), now.plusSeconds(3600),
                                                                     expired ? now.minusSeconds(1) : now.plusSeconds(30));
                        for (int i = 0; i < 2; i++) {
                            AuthenticationResponse response = authenticate(provider, source);
                            assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                            assertThat(response.statusCode().orElseThrow(), is(503));
                            assertThat(response.user().isEmpty(), is(true));
                            assertThat(response.responseHeaders().containsKey(HeaderNames.LOCATION.defaultCase()), is(false));
                            List<String> cookies = response.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase());
                            assertThat(cookies.isEmpty(), is(false));
                            cookies.stream().map(SetCookie::parse).forEach(cookie -> assertThat(cookie.value(), is("")));
                            assertThat(TOKEN_REQUEST_COUNT.get(), is(1));
                        }
                        release.countDown();
                        load.get(5, TimeUnit.SECONDS);
                        AuthenticationResponse late = authenticate(provider, source);
                        assertThat(late.statusCode().orElseThrow(), is(503));
                        assertThat(TOKEN_REQUEST_COUNT.get(), is(1));
                    } finally {
                        release.countDown();
                    }
                } finally {
                    release.countDown();
                    keys.stop();
                }
            }
        }
    }

    @Test
    void browserRefreshDoesNotRequireCustomApiPrincipalClaim(URI serverUri) {
        String refreshedAccessToken = signedAccessToken(_ -> { });
        responseBody = refreshResponse(refreshedAccessToken, ROTATED_REFRESH_TOKEN).toString();
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .from(tenantWithJwtAccessTokenValidation(serverUri))
                .subjectMapping(mapping -> mapping.principalIdClaimPaths(List.of("api_account")))
                .buildPrototype();
        Instant now = Instant.now();
        SetCookie cookie = localAuthenticationCookie(tenant, now.minusSeconds(60), now.plusSeconds(3600), now.minusSeconds(1));

        AuthenticationResponse response = authenticate(tenant, cookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().id(), is(issuerSubjectPrincipalId()));
        assertThat(storedLocalAuthenticationResult(response, tenant).accessToken(), is(refreshedAccessToken));
    }

    @Test
    void browserRefreshDoesNotApplyProtectedResourceJwtValidation(URI serverUri) {
        String refreshedAccessToken = "opaque-token-for-another-resource";
        responseBody = refreshResponse(refreshedAccessToken, ROTATED_REFRESH_TOKEN).toString();
        OidcTenantConfig tenant = tenantWithJwtAccessTokenValidation(serverUri);
        for (int secondsUntilExpiry : List.of(-1, 30)) {
            Instant now = Instant.now();
            SetCookie cookie = localAuthenticationCookie(tenant, now.minusSeconds(60), now.plusSeconds(3600),
                                                        now.plusSeconds(secondsUntilExpiry));

            AuthenticationResponse response = authenticate(tenant, cookie);

            assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(response.user().orElseThrow().principal().id(), is(issuerSubjectPrincipalId()));
            assertThat(storedLocalAuthenticationResult(response, tenant).accessToken(), is(refreshedAccessToken));
        }
    }

    @Test
    void browserRefreshDoesNotInvokeProtectedResourceIntrospection(URI serverUri) {
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

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(storedLocalAuthenticationResult(response, tenant).accessToken(), is(REFRESHED_ACCESS_TOKEN));
        assertThat(RECORDED_INTROSPECTION_REQUEST.get(), is(nullValue()));
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
        assertThat(storedLocalAuthenticationResult(response, tenant).idToken().rawToken(), is(refreshedIdToken));
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
                                                                        _ -> { });

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().getName(), is("refetched-user"));
        assertThat(RECORDED_USER_INFO_AUTHORIZATION.get(), is("Bearer " + REFRESHED_ACCESS_TOKEN));
        OidcLocalAuthenticationResult stored = storedLocalAuthenticationResult(response, tenant);
        assertThat(stored.userInfo().orElseThrow().stringValue("preferred_username").orElse(""),
                   is("refetched-user"));
    }

    @Test
    void refreshRequeriesEncryptedUserInfo(URI serverUri) {
        JsonObject claims = userInfoResponse(SUBJECT, "encrypted-refetched-user");
        userInfoResponseContentType = "application/jwt";
        userInfoResponseBody = EncryptedJwt.payloadBuilder(claims.toString().getBytes(StandardCharsets.UTF_8))
                .jwks(encryptKeys, "encrypt-rsa")
                .algorithm(EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256)
                .encryption(EncryptedJwt.SupportedEncryption.A256GCM)
                .build()
                .token();
        OidcTenantConfig tenant = tenantWithUserInfo(serverUri, userInfo -> userInfo.jwt(jwt -> jwt
                .encryptionAlgorithm("RSA-OAEP-256")
                .contentEncryptionAlgorithm("A256GCM")
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype())));
        Instant now = Instant.now();
        SetCookie localAuthenticationCookie = localAuthenticationCookie(tenant,
                                                                        now.minusSeconds(60),
                                                                        now.plusSeconds(3600),
                                                                        now.minusSeconds(1),
                                                                        OLD_REFRESH_TOKEN,
                                                                        JsonObject.builder()
                                                                                .set("sub", SUBJECT)
                                                                                .build(),
                                                                        _ -> { });

        AuthenticationResponse response = authenticate(tenant, localAuthenticationCookie);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().getName(), is("encrypted-refetched-user"));
        assertThat(RECORDED_USER_INFO_AUTHORIZATION.get(), is("Bearer " + REFRESHED_ACCESS_TOKEN));
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
                                                                        _ -> { });

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
        assertThat(storedLocalAuthenticationResult(response, tenant).expiresAt(), is(refreshedExpiration));
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
        int requestNumber = TOKEN_REQUEST_COUNT.incrementAndGet();
        TokenEndpointResponder responder = TOKEN_ENDPOINT_RESPONDER.get();
        if (responder != null) {
            responder.respond(requestNumber, response);
            return;
        }
        sendTokenResponse(response, responseStatus, responseBody);
    }

    private static void sendTokenResponse(ServerResponse response, int status, String body) {
        response.status(status)
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .header(HeaderNames.CACHE_CONTROL, "no-store")
                .header(HeaderNames.PRAGMA, "no-cache")
                .send(body);
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
                .header(HeaderNames.CONTENT_TYPE, userInfoResponseContentType)
                .send(userInfoResponseBody);
    }

    private static OidcTenantConfig tenant(URI serverUri) {
        return tenant(serverUri, List.of());
    }

    private static OidcTenantConfig tenantWithAuthorizationCodeResources(URI serverUri) {
        return tenant(serverUri, List.of("https://api.example.com", "urn:example:contacts"));
    }

    private static OidcTenantConfig tenant(URI serverUri, List<String> authorizationCodeResources) {
        return tenant(serverUri, authorizationCodeResources, _ -> { });
    }

    private static OidcTenantConfig tenant(
            URI serverUri,
            List<String> authorizationCodeResources,
            Consumer<OidcAuthorizationCodeConfig.Builder> authorizationCodeCustomizer) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(serverUri.resolve("token"))
                        .jwksUri(serverUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> {
                    it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                            .scopes(List.of("openid", "profile"))
                            .resources(authorizationCodeResources);
                    authorizationCodeCustomizer.accept(it);
                })
                .cookies(it -> it.password(COOKIE_PASSWORD))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantWithJwtAccessTokenValidation(URI serverUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
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
                .cookies(it -> it.password(COOKIE_PASSWORD))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantWithIntrospectionAccessTokenValidation(URI serverUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(serverUri.resolve("token"))
                        .introspectionEndpointUri(serverUri.resolve("introspect"))
                        .jwksUri(serverUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .protectedResource(it -> it.enabled(false)
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience(AUDIENCE)))
                .cookies(it -> it.password(COOKIE_PASSWORD))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantWithUserInfo(URI serverUri) {
        return tenantWithUserInfo(serverUri, _ -> { });
    }

    private static OidcTenantConfig tenantWithUserInfo(URI serverUri,
                                                       Consumer<OidcUserInfoConfig.Builder> userInfo) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(serverUri.resolve("token"))
                        .userInfoEndpointUri(serverUri.resolve("userinfo"))
                        .jwksUri(serverUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .userInfo(userInfo)
                .cookies(it -> it.password(COOKIE_PASSWORD))
                .buildPrototype();
    }

    private static AuthenticationResponse authenticate(OidcTenantConfig tenant, SetCookie localAuthenticationCookie) {
        return authenticate(provider(tenant), localAuthenticationCookie);
    }

    private static AuthenticationResponse authenticate(OidcProvider provider, SetCookie localAuthenticationCookie) {
        return authenticate(provider, localAuthenticationCookie, SecurityTime.create());
    }

    private static AuthenticationResponse authenticate(OidcProvider provider,
                                                       SetCookie localAuthenticationCookie,
                                                       SecurityTime securityTime) {
        return provider.authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                .targetUri(ORIGINAL_URI)
                .time(securityTime)
                .header(HeaderNames.COOKIE.defaultCase(),
                        localAuthenticationCookie.name() + "=" + localAuthenticationCookie.value())
                .build()));
    }

    private static AuthenticationResponse authenticate(OidcProvider provider, LocalAuthenticationCookies cookies) {
        return provider.authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                .targetUri(ORIGINAL_URI)
                .header(HeaderNames.COOKIE.defaultCase(),
                        cookies.localAuthentication().name() + "=" + cookies.localAuthentication().value()
                                + "; " + cookies.generationCookie().name() + "=" + cookies.generationCookie().value())
                .build()));
    }

    private static OidcProvider provider(OidcTenantConfig tenant) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .buildPrototype());
    }

    private static LocalAuthenticationCookies localAuthenticationCookies(OidcTenantConfig tenant,
                                                                         Instant createdAt,
                                                                         Instant expiresAt,
                                                                         Instant accessTokenExpiresAt) {
        OidcCookieStateHandler cookieStateHandler = OidcCookieStateHandler.create("default", tenant);
        OidcCookieStateHandler.BrowserSessionGeneration generation =
                cookieStateHandler.createBrowserSessionGeneration();
        SetCookie localAuthentication = localAuthenticationCookie(tenant,
                                                                  createdAt,
                                                                  expiresAt,
                                                                  accessTokenExpiresAt,
                                                                  OLD_REFRESH_TOKEN,
                                                                  null,
                                                                  _ -> { },
                                                                  generation.value());
        return new LocalAuthenticationCookies(localAuthentication, generation.cookie(), generation.value());
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
                                         _ -> { });
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
        return localAuthenticationCookie(tenant,
                                         createdAt,
                                         expiresAt,
                                         accessTokenExpiresAt,
                                         refreshToken,
                                         userInfo,
                                         idTokenCustomizer,
                                         null);
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant,
                                                       Instant createdAt,
                                                       Instant expiresAt,
                                                       Instant accessTokenExpiresAt,
                                                       String refreshToken,
                                                       JsonObject userInfo,
                                                       Consumer<Jwt.Builder> idTokenCustomizer,
                                                       String browserSessionGeneration) {
        String idToken = signedIdToken(idTokenCustomizer);
        SignedJwt signedJwt = SignedJwt.parseToken(idToken);
        return OidcCookieStateHandler.create("default", tenant)
                .createLocalAuthenticationResultCookies(OidcLocalAuthenticationResult.fromStoredValues(
                        OidcLocalAuthenticationState.builder()
                                .tenantId("default")
                                .idToken(new OidcValidatedIdToken(idToken, false, signedJwt, signedJwt.getJwt()))
                                .accessToken(OLD_ACCESS_TOKEN)
                                .tokenType("Bearer")
                                .refreshToken(Optional.ofNullable(refreshToken))
                                .browserSessionGeneration(Optional.ofNullable(browserSessionGeneration))
                                .scope("openid profile")
                                .userInfo(Optional.ofNullable(userInfo))
                                .createdAt(createdAt)
                                .expiresAt(expiresAt)
                                .accessTokenExpiresAt(Optional.ofNullable(accessTokenExpiresAt))
                                .buildPrototype()), Map.of(), Instant.now()).getFirst();
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

    private static String issuerSubjectPrincipalId() {
        return "oidc-sub:" + base64Url(ISSUER.toString()) + "." + base64Url(SUBJECT);
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
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
                .jwtId("jwt-id")
                .addPayloadClaim("client_id", CLIENT_ID)
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

    private static void assertAccessToken(AuthenticationResponse response, String expectedToken) {
        assertThat(response.user()
                           .orElseThrow()
                           .publicCredential(TokenCredential.class)
                           .orElseThrow()
                           .token(),
                   is(expectedToken));
    }

    private static OidcLocalAuthenticationResult storedLocalAuthenticationResult(AuthenticationResponse response,
                                                                                OidcTenantConfig tenant) {
        return storedLocalAuthenticationResult(response,
                                               tenant,
                                               OidcCookieStateHandler.create("default", tenant));
    }

    private static OidcLocalAuthenticationResult storedLocalAuthenticationResult(
            AuthenticationResponse response,
            OidcTenantConfig tenant,
            OidcCookieStateHandler cookieStateHandler) {
        String localAuthenticationCookieName = tenant.cookies().localAuthenticationCookieName();
        List<String> setCookies = response.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase());
        Map<String, List<String>> cookieSet = new LinkedHashMap<>();
        setCookies.stream().map(SetCookie::parse)
                .forEach(cookie -> cookieSet.put(cookie.name(), List.of(cookie.value())));
        assertThat(cookieSet.containsKey(localAuthenticationCookieName), is(true));
        return cookieStateHandler.readLocalAuthenticationResult(cookieSet,
                                                                Instant.now(),
                                                                OidcIdTokenDecryptor.create(tenant))
                .orElseThrow();
    }

    private static Map<String, List<String>> formParameters(Parameters parameters) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (String name : parameters.names()) {
            result.put(name, parameters.all(name));
        }
        return result;
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for test synchronization");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted during test synchronization", e);
        }
    }

    @FunctionalInterface
    private interface TokenEndpointResponder {
        void respond(int requestNumber, ServerResponse response);
    }

    private record LocalAuthenticationCookies(SetCookie localAuthentication,
                                              SetCookie generationCookie,
                                              String generation) {
    }

    private record RecordedRequest(String authorization, Map<String, List<String>> formParameters) {
    }
}
