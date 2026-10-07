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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.configurable.Resource;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.oidc.next.spi.OidcTenantAdapter;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

@ServerTest
class OidcCallbackTokenLifetimeTest {
    private static final String ISSUER = "https://issuer.example";
    private static final String CLIENT_ID = "lifetime-client";
    private static final Duration SESSION_LIFETIME = Duration.ofMinutes(5);
    private static final AtomicReference<String> NONCE = new AtomicReference<>();
    private static final AtomicReference<Optional<Long>> EXPIRES_IN = new AtomicReference<>();
    private static final AtomicReference<Instant> TOKEN_RESPONSE_TIME = new AtomicReference<>();
    private static final AtomicReference<Gate> USER_INFO_GATE = new AtomicReference<>();
    private static final AtomicInteger TOKEN_REQUESTS = new AtomicInteger();

    private static JwkKeys signKeys;

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.get("/jwks", (_, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(Resource.create("oidc-next-verify-public-jwk.json").string()));
        routing.post("/token", (_, response) -> {
            TOKEN_REQUESTS.incrementAndGet();
            Instant now = Instant.now();
            Jwt jwt = Jwt.builder().algorithm("RS256").keyId("verify-rsa").issuer(ISSUER).subject("alice")
                    .addAudience(CLIENT_ID).nonce(NONCE.get()).issueTime(now).expirationTime(now.plusSeconds(3600)).build();
            String idToken = SignedJwt.sign(jwt, signKeys.forKeyId("sign-rsa").orElseThrow()).tokenContent();
            JsonObject.Builder token = JsonObject.builder().set("access_token", "access-token").set("token_type", "Bearer")
                    .set("id_token", idToken).set("refresh_token", "refresh-token");
            EXPIRES_IN.get().ifPresent(lifetime -> token.set("expires_in", lifetime));
            TOKEN_RESPONSE_TIME.set(Instant.now());
            response.header(HeaderValues.CONTENT_TYPE_JSON).header(HeaderNames.CACHE_CONTROL, "no-store")
                    .header(HeaderNames.PRAGMA, "no-cache").send(token.build());
        });
        routing.get("/userinfo", (_, response) -> {
            awaitRelease(USER_INFO_GATE.get());
            response.header(HeaderValues.CONTENT_TYPE_JSON).send(JsonObject.builder().set("sub", "alice").build());
        });
    }

    @BeforeEach
    void setUp() {
        TOKEN_REQUESTS.set(0);
        TOKEN_RESPONSE_TIME.set(null);
        USER_INFO_GATE.set(new Gate(new CountDownLatch(1), new CountDownLatch(1)));
    }

    @Test
    void callbackUsesTokenExchangeReferenceForAccessExpiryAndCreationTimeForSessionLifetime(URI serverUri) throws Exception {
        verifyCallback(serverUri, Optional.of(120L), DelayPhase.USER_INFO, false);
    }

    @Test
    void callbackRejectsAccessTokenThatExpiresDuringUserInfo(URI serverUri) throws Exception {
        verifyCallback(serverUri, Optional.of(1L), DelayPhase.USER_INFO, true);
    }

    @Test
    void callbackRejectsAccessTokenThatExpiresDuringSubjectMapping(URI serverUri) throws Exception {
        verifyCallback(serverUri, Optional.of(1L), DelayPhase.SUBJECT_MAPPING, true);
    }

    @Test
    void callbackPreservesUnknownAccessTokenLifetimeWithUserInfo(URI serverUri) throws Exception {
        verifyCallback(serverUri, Optional.empty(), DelayPhase.USER_INFO, false);
    }

    private static void awaitRelease(Gate gate) {
        gate.entered().countDown();
        try {
            if (!gate.release().await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Test did not release callback processing");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted callback fixture", e);
        }
    }

    private void verifyCallback(URI serverUri, Optional<Long> lifetime, DelayPhase phase, boolean expire) throws Exception {
        EXPIRES_IN.set(lifetime);
        Gate mappingGate = new Gate(new CountDownLatch(1), new CountDownLatch(1));
        OidcTenantConfig.Builder builder = OidcTenantConfig.builder().issuer(ISSUER).clientId(CLIENT_ID)
                .clientSecret("lifetime-client-secret")
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(URI.create(ISSUER + "/authorize"))
                        .tokenEndpointUri(serverUri.resolve("token")).jwksUri(serverUri.resolve("jwks"))
                        .userInfoEndpointUri(serverUri.resolve("userinfo")).tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(URI.create("/oidc/callback")))
                .userInfo(_ -> { })
                .cookies(cookies -> cookies.localAuthenticationLifetime(SESSION_LIFETIME)
                        .protection(protection -> protection.password("lifetime-cookie-password")));
        if (phase == DelayPhase.SUBJECT_MAPPING) {
            USER_INFO_GATE.get().release().countDown();
            builder.adapter(new OidcTenantAdapter() {
                @Override
                public String name() {
                    return "lifetime-test";
                }

                @Override
                public String type() {
                    return "lifetime-test";
                }

                @Override
                public Subject mapSubject(OidcTenantConfig tenant, Subject subject) {
                    awaitRelease(mappingGate);
                    return subject;
                }
            });
        }
        OidcTenantConfig tenant = builder.buildPrototype();
        OidcProviderConfig config = OidcProviderConfig.builder().putTenant("default", tenant).buildPrototype();
        try (OidcProvider provider = OidcProvider.create(config)) {
            // The OP is extension-managed; this RP has a per-scenario provider configured with the OP's injected URI.
            WebServer rp = WebServer.builder().host("127.0.0.1").port(0).addFeature(OidcFeature.create(provider)).build().start();
            WebClient client = WebClient.builder().baseUri(URI.create("http://127.0.0.1:" + rp.port())).build();
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                var login = provider.authenticate(OidcProviderTest.request(null, SecurityEnvironment.builder()
                        .targetUri(URI.create("http://127.0.0.1:" + rp.port() + "/resource")).transport("http").build()));
                assertThat(login.statusCode().orElseThrow(), is(303));
                UriQuery query = UriQuery.create(URI.create(login.responseHeaders().get("Location").getFirst()));
                NONCE.set(query.get("nonce"));
                String cookies = String.join("; ", login.responseHeaders().get("Set-Cookie").stream().map(SetCookie::parse)
                        .map(cookie -> cookie.name() + "=" + cookie.value()).toList());
                if (expire) {
                    cookies += "; " + tenant.cookies().localAuthenticationCookieName() + ".3=previous-piece";
                }
                String callbackCookies = cookies;
                Instant beforeCallback = Instant.now();
                var callback = executor.submit(() -> {
                    try (HttpClientResponse response = client.get("/oidc/callback").followRedirects(false)
                            .queryParam("code", "authorization-code").queryParam("state", query.get("state"))
                            .header(HeaderNames.COOKIE, callbackCookies).request()) {
                        return new CallbackResponse(response.status(), List.copyOf(response.headers().get(HeaderNames.SET_COOKIE)
                                .allValues()), response.headers().first(HeaderNames.LOCATION),
                                                    response.entity().hasEntity() ? response.as(String.class) : "");
                    }
                });
                try {
                    Gate delayed = phase == DelayPhase.USER_INFO ? USER_INFO_GATE.get() : mappingGate;
                    assertThat(delayed.entered().await(10, TimeUnit.SECONDS), is(true));
                    Instant generatedAt = TOKEN_RESPONSE_TIME.get();
                    if (expire) {
                        Instant expiresAt = generatedAt.plusSeconds(lifetime.orElseThrow());
                        Duration remaining = Duration.between(Instant.now(), expiresAt.plusMillis(1));
                        if (remaining.isPositive()) {
                            // Real elapsed time is the contract: keep processing blocked until the advertised expiry.
                            new CountDownLatch(1).await(remaining.toNanos(), TimeUnit.NANOSECONDS);
                        }
                        assertThat(Instant.now(), greaterThanOrEqualTo(expiresAt));
                    }
                    delayed.release().countDown();
                    CallbackResponse response = callback.get(10, TimeUnit.SECONDS);
                    assertThat(TOKEN_REQUESTS.get(), is(1));
                    if (expire) {
                        assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                        assertThat(response.body(), is("Access token expired during authentication"));
                        assertThat(response.location(), is(Optional.empty()));
                        List<SetCookie> sessionUpdates = response.cookies().stream().map(SetCookie::parse)
                                .filter(cookie -> cookie.name().equals(tenant.cookies().localAuthenticationCookieName())
                                        || cookie.name().startsWith(tenant.cookies().localAuthenticationCookieName() + "."))
                                .toList();
                        assertThat(sessionUpdates, hasSize(16));
                        assertThat(sessionUpdates.stream().map(SetCookie::value).toList(), everyItem(is("")));
                    } else {
                        assertThat(response.status(), is(Status.SEE_OTHER_303));
                        Map<String, List<String>> storedCookies = new HashMap<>();
                        response.cookies().stream().map(SetCookie::parse).filter(cookie -> !cookie.value().isEmpty())
                                .forEach(cookie -> storedCookies.put(cookie.name(), List.of(cookie.value())));
                        OidcLocalAuthenticationResult stored = OidcCookieStateHandler.create("default", tenant)
                                .readLocalAuthenticationResult(storedCookies, Instant.now(), OidcIdTokenDecryptor.create(tenant))
                                .orElseThrow();
                        assertThat(stored.expiresAt(), is(stored.createdAt().plus(SESSION_LIFETIME)));
                        assertThat(stored.createdAt(), greaterThanOrEqualTo(generatedAt));
                        if (lifetime.isPresent()) {
                            Instant expiry = stored.accessTokenExpiresAt().orElseThrow();
                            assertThat(expiry, greaterThanOrEqualTo(beforeCallback.plusSeconds(lifetime.orElseThrow())));
                            assertThat(expiry, lessThanOrEqualTo(generatedAt.plusSeconds(lifetime.orElseThrow())));
                        } else {
                            assertThat(stored.accessTokenExpiresAt(), is(Optional.empty()));
                        }
                    }
                } finally {
                    USER_INFO_GATE.get().release().countDown();
                    mappingGate.release().countDown();
                }
            } finally {
                client.closeResource();
                rp.stop();
            }
        }
    }

    private enum DelayPhase {
        USER_INFO,
        SUBJECT_MAPPING
    }

    private record Gate(CountDownLatch entered, CountDownLatch release) {
    }

    private record CallbackResponse(Status status, List<String> cookies, Optional<String> location, String body) {
    }
}
