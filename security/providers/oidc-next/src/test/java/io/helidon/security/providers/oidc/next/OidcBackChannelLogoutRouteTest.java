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
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;
import io.helidon.webclient.api.HttpClientRequest;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcBackChannelLogoutRouteTest {
    private static final String ISSUER = "https://issuer.example";
    private static final String CLIENT_ID = "client-id";
    private static final String SUBJECT = "alice";
    private static final String SID = "op-session-1";
    private static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private static JwkKeys signKeys;
    private static URI verificationUri;

    @BeforeAll
    static void initKeys() throws Exception {
        signKeys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
        verificationUri = OidcBackChannelLogoutRouteTest.class.getClassLoader()
                .getResource("oidc-next-verify-public-jwk.json").toURI();
    }

    @Test
    void signedOpPostRevokesCookieOnNextRequestWithoutBrowserAtTheWebhook() {
        OidcTenantConfig tenant = tenant();
        try (OidcProvider provider = provider(tenant)) {
            WebClient client = WebClient.builder().build();
            SetCookie cookie = localAuthenticationCookie(provider, tenant, SID);
            HttpRouting.Builder routing = HttpRouting.builder();
            OidcFeature.create(provider).setup(routing);
            WebServer server = WebServer.builder().host("127.0.0.1").port(0).addRouting(routing).build().start();
            try {
                assertThat(authenticate(provider, cookie).status(), is(SecurityResponse.SecurityStatus.SUCCESS));

                URI uri = URI.create("http://127.0.0.1:" + server.port() + "/oidc/backchannel");
                try (HttpClientResponse response = client.post().uri(uri)
                        .submit(Parameters.builder("logout")
                                        .add("logout_token", logoutToken(_ -> { }))
                                        .add("ignored_parameter", "ignored")
                                        .build())) {
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.headers().first(HeaderNames.CACHE_CONTROL).orElse(""), is("no-store"));
                }

                AuthenticationResponse rejected = authenticate(provider, cookie);
                assertThat(rejected.status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
                assertThat(rejected.statusCode().orElseThrow(), is(Status.SEE_OTHER_303_CODE));
                assertThat(rejected.responseHeaders().get(HeaderNames.SET_COOKIE.defaultCase())
                                   .stream().map(SetCookie::parse)
                                   .filter(setCookie -> setCookie.name().equals(tenant.cookies().localAuthenticationCookieName()))
                                   .findFirst().orElse(null), is(notNullValue()));
            } finally {
                server.stop();
                client.closeResource();
            }
        }
    }

    @Test
    void invalidLogoutTokenReturns400WithoutChangingAnExistingSession() {
        OidcTenantConfig tenant = tenant();
        try (OidcProvider provider = provider(tenant)) {
            WebClient client = WebClient.builder().build();
            SetCookie cookie = localAuthenticationCookie(provider, tenant, SID);
            HttpRouting.Builder routing = HttpRouting.builder();
            OidcFeature.create(provider).setup(routing);
            WebServer server = WebServer.builder().host("127.0.0.1").port(0).addRouting(routing).build().start();
            try {
                URI uri = URI.create("http://127.0.0.1:" + server.port() + "/oidc/backchannel");
                try (HttpClientResponse response = client.post().uri(uri)
                        .submit(Parameters.builder("logout")
                                        .add("logout_token", logoutToken(builder -> builder.issuer("https://wrong.example")))
                                        .build())) {
                    assertThat(response.status(), is(Status.BAD_REQUEST_400));
                    assertThat(response.headers().first(HeaderNames.CACHE_CONTROL).orElse(""), is("no-store"));
                    assertThat(response.entity().hasEntity(), is(false));
                }
                assertThat(authenticate(provider, cookie).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            } finally {
                server.stop();
                client.closeResource();
            }
        }
    }

    @Test
    void malformedLogoutPostsDoNotRevokeAnExistingSession() {
        TestStore store = new TestStore();
        OidcTenantConfig tenant = withStore(store);
        try (OidcProvider provider = provider(tenant)) {
            SetCookie cookie = localAuthenticationCookie(provider, tenant, SID);
            WebClient client = WebClient.builder().build();
            WebServer server = logoutServer(provider);
            try {
                URI uri = URI.create("http://127.0.0.1:" + server.port() + "/oidc/backchannel");
                String token = logoutToken(_ -> { });
                List<Map.Entry<String, String>> malformedForms = List.of(
                        Map.entry("empty body", ""),
                        Map.entry("no token", "ignored=ok"),
                        Map.entry("bare field", "logout_token"),
                        Map.entry("empty token", "logout_token="),
                        Map.entry("whitespace token", "logout_token=+++"),
                        Map.entry("duplicate same token", "logout_token=" + token + "&logout_token=" + token),
                        Map.entry("duplicate different token", "logout_token=" + token + "&logout_token=invalid"),
                        Map.entry("invalid percent in name", "logout%ZZ_token=" + token),
                        Map.entry("invalid percent in value", "logout_token=%ZZ"));
                for (Map.Entry<String, String> testCase : malformedForms) {
                    try (HttpClientResponse response = postRawLogout(client, uri,
                                                                      "application/x-www-form-urlencoded",
                                                                      testCase.getValue())) {
                        assertBadLogoutResponse(response, testCase.getKey());
                    }
                    assertThat(testCase.getKey(), store.revocations.get(), is(0));
                    assertThat(testCase.getKey(), authenticate(provider, cookie).status(),
                               is(SecurityResponse.SecurityStatus.SUCCESS));
                }

                String validForm = "logout_token=" + token;
                for (String wrongMediaType : List.of("application/json", "text/plain")) {
                    try (HttpClientResponse response = postRawLogout(client, uri, wrongMediaType, validForm)) {
                        assertBadLogoutResponse(response, wrongMediaType);
                    }
                    assertThat(store.revocations.get(), is(0));
                    assertThat(authenticate(provider, cookie).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                }

                String oversizedForm = validForm + "&ignored=" + "x".repeat(1024 * 1024);
                try (HttpClientResponse response = postRawLogout(client, uri,
                                                                  "application/x-www-form-urlencoded",
                                                                  oversizedForm)) {
                    assertBadLogoutResponse(response, "oversized form");
                }
                assertThat(store.revocations.get(), is(0));
                assertThat(authenticate(provider, cookie).status(), is(SecurityResponse.SecurityStatus.SUCCESS));

                // Unknown form fields must be ignored; an invalid request must not consume the valid Logout Token.
                try (HttpClientResponse response = postRawLogout(client, uri,
                                                                  "application/x-www-form-urlencoded; charset=UTF-8",
                                                                  "ignored=ok&" + validForm)) {
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.headers().first(HeaderNames.CACHE_CONTROL).orElse(""), is("no-store"));
                }
                assertThat(store.revocations.get(), is(1));
                assertThat(authenticate(provider, cookie).status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
            } finally {
                server.stop();
                client.closeResource();
            }
        }
    }

    @Test
    void fixedRegisteredQueryIsRequiredAndAdditionalQueryParametersAreAllowed() {
        TestStore store = new TestStore();
        OidcTenantConfig tenant = OidcTenantConfig.builder(withStore(store))
                .logout(logout -> logout.backChannel(backChannel -> backChannel
                        .uri(URI.create("http://127.0.0.1/oidc/backchannel?tenant=default&tag=one&tag=two"))
                        .store(store)))
                .buildPrototype();
        try (OidcProvider provider = provider(tenant)) {
            SetCookie cookie = localAuthenticationCookie(provider, tenant, SID);
            WebClient client = WebClient.builder().build();
            WebServer server = logoutServer(provider);
            try {
                String endpoint = "http://127.0.0.1:" + server.port() + "/oidc/backchannel";
                String form = "logout_token=" + logoutToken(_ -> { });
                List<Map.Entry<String, String>> invalidQueries = List.of(
                        Map.entry("missing query", ""),
                        Map.entry("wrong tenant", "?tenant=other&tag=one&tag=two"),
                        Map.entry("duplicated tenant", "?tenant=default&tenant=default&tag=one&tag=two"),
                        Map.entry("missing registered value", "?tenant=default&tag=one"),
                        Map.entry("changed registered value", "?tenant=default&tag=one&tag=other"));
                for (Map.Entry<String, String> testCase : invalidQueries) {
                    try (HttpClientResponse response = postRawLogout(client,
                                                                      URI.create(endpoint + testCase.getValue()),
                                                                      "application/x-www-form-urlencoded", form)) {
                        assertBadLogoutResponse(response, testCase.getKey());
                    }
                    assertThat(testCase.getKey(), store.revocations.get(), is(0));
                    assertThat(testCase.getKey(), authenticate(provider, cookie).status(),
                               is(SecurityResponse.SecurityStatus.SUCCESS));
                }

                // The registered query must survive if the OP appends its own query parameter.
                URI validUri = URI.create(endpoint + "?tenant=default&tag=one&tag=two&op=notice");
                try (HttpClientResponse response = postRawLogout(client, validUri,
                                                                  "application/x-www-form-urlencoded", form)) {
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.headers().first(HeaderNames.CACHE_CONTROL).orElse(""), is("no-store"));
                }
                assertThat(store.revocations.get(), is(1));
                assertThat(authenticate(provider, cookie).status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
            } finally {
                server.stop();
                client.closeResource();
            }
        }
    }

    @Test
    void exhaustedLogoutWorkCapacityRejectsAndLaterAcceptsTheSameToken() {
        TestStore store = new TestStore();
        OidcTenantConfig tenant = OidcTenantConfig.builder(withStore(store))
                .logout(logout -> logout.backChannel(backChannel -> backChannel
                        .uri(URI.create("http://127.0.0.1/oidc/backchannel"))
                        .store(store)
                        .remoteWork(remoteWork -> remoteWork.maxConcurrent(1).maxQueued(0))))
                .buildPrototype();
        try (OidcProvider provider = provider(tenant)) {
            SetCookie cookie = localAuthenticationCookie(provider, tenant, SID);
            WebClient client = WebClient.builder().build();
            WebServer server = logoutServer(provider);
            try {
                URI uri = URI.create("http://127.0.0.1:" + server.port() + "/oidc/backchannel");
                String token = logoutToken(_ -> { });
                OidcRemoteWorkLimiter limiter = provider.tenantRuntimeRegistry()
                        .logoutWorkLimiter("default").orElseThrow();
                // Occupy the exact permit that the route must acquire, without relying on thread timing or sleeps.
                try (OidcRemoteWorkLimiter.Permit _ = limiter.acquireActive().orElseThrow()) {
                    try (HttpClientResponse response = postRawLogout(client, uri,
                                                                      "application/x-www-form-urlencoded",
                                                                      "logout_token=" + token)) {
                        assertBadLogoutResponse(response, "capacity exhausted");
                    }
                    assertThat(limiter.activeCount(), is(1));
                    assertThat(store.revocations.get(), is(0));
                    assertThat(authenticate(provider, cookie).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                }

                assertThat(limiter.activeCount(), is(0));
                try (HttpClientResponse response = postRawLogout(client, uri,
                                                                  "application/x-www-form-urlencoded",
                                                                  "logout_token=" + token)) {
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.headers().first(HeaderNames.CACHE_CONTROL).orElse(""), is("no-store"));
                }
                assertThat(limiter.activeCount(), is(0));
                assertThat(store.revocations.get(), is(1));
                assertThat(authenticate(provider, cookie).status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
            } finally {
                server.stop();
                client.closeResource();
            }
        }
    }

    @Test
    void subjectOnlyLogoutRevokesExistingSessionsButNotNewLoginOrDuplicateDelivery() {
        OidcTenantConfig tenant = tenant();
        try (OidcProvider provider = provider(tenant)) {
            WebClient client = WebClient.builder().build();
            SetCookie first = localAuthenticationCookie(provider, tenant, SID);
            SetCookie second = localAuthenticationCookie(provider, tenant, "op-session-2");
            HttpRouting.Builder routing = HttpRouting.builder();
            OidcFeature.create(provider).setup(routing);
            WebServer server = WebServer.builder().host("127.0.0.1").port(0).addRouting(routing).build().start();
            try {
                URI uri = URI.create("http://127.0.0.1:" + server.port() + "/oidc/backchannel");
                String subOnly = logoutToken(builder -> builder.removePayloadClaim("sid"));
                assertThat(postLogout(client, uri, subOnly), is(Status.OK_200));
                assertThat(authenticate(provider, first).status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
                assertThat(authenticate(provider, second).status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));

                SetCookie newLogin = localAuthenticationCookie(provider, tenant, "op-session-new",
                        SignedJwt.parseToken(subOnly).getJwt().issueTime().orElseThrow());
                assertThat(authenticate(provider, newLogin).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                assertThat(postLogout(client, uri, subOnly), is(Status.OK_200));
                assertThat(authenticate(provider, newLogin).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            } finally {
                server.stop();
                client.closeResource();
            }
        }
    }

    @Test
    void oldProtectedCookiesContinueAfterProviderRestartEvenIfLogoutWasReceived() {
        OidcTenantConfig tenant = tenant();
        SetCookie oldCookie;
        try (OidcProvider first = provider(tenant)) {
            oldCookie = localAuthenticationCookie(first, tenant, SID);
            assertThat(authenticate(first, oldCookie).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            Instant now = Instant.now();
            first.tenantRuntimeRegistry().logoutStore("default").orElseThrow()
                    .revoke(new OidcBackChannelLogoutStore.LogoutEvent("default", ISSUER,
                                                                        Optional.of(SUBJECT),
                                                                        Optional.of(SID),
                                                                        "logout-before-restart", now,
                                                                        now.plusSeconds(120)),
                            now.plusSeconds(3600));
            // The browser has not returned to receive the clearing cookie before the process restarts.
        }
        try (OidcProvider restarted = provider(tenant)) {
            assertThat(authenticate(restarted, oldCookie).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            Instant now = Instant.now();
            restarted.tenantRuntimeRegistry().logoutStore("default").orElseThrow()
                    .revoke(new OidcBackChannelLogoutStore.LogoutEvent("default", ISSUER,
                                                                        Optional.of(SUBJECT),
                                                                        Optional.of(SID),
                                                                        "logout-after-restart", now,
                                                                        now.plusSeconds(120)),
                            now.plusSeconds(3600));
            assertThat(authenticate(restarted, oldCookie).status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
            SetCookie newCookie = localAuthenticationCookie(restarted, tenant, "op-session-new");
            assertThat(authenticate(restarted, newCookie).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        }
    }

    @Test
    void separateProviderInstancesUseTheSameApplicationSuppliedStore() {
        TestStore shared = new TestStore();
        OidcTenantConfig tenant = withStore(shared);
        try (OidcProvider receiver = provider(tenant);
             OidcProvider authenticator = provider(tenant)) {
            WebClient client = WebClient.builder().build();
            SetCookie cookie = localAuthenticationCookie(authenticator, tenant, SID);
            HttpRouting.Builder routing = HttpRouting.builder();
            OidcFeature.create(receiver).setup(routing);
            WebServer server = WebServer.builder().host("127.0.0.1").port(0).addRouting(routing).build().start();
            try {
                assertThat(authenticate(authenticator, cookie).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                URI uri = URI.create("http://127.0.0.1:" + server.port() + "/oidc/backchannel");
                assertThat(postLogout(client, uri, logoutToken(_ -> { })), is(Status.OK_200));
                assertThat(authenticate(authenticator, cookie).status(),
                           is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
            } finally {
                server.stop();
                client.closeResource();
            }
        }
    }

    @Test
    void unavailableStoreNeitherAuthenticatesCookieNorAcknowledgesLogout() {
        TestStore store = new TestStore();
        OidcTenantConfig tenant = withStore(store);
        try (OidcProvider provider = provider(tenant)) {
            WebClient client = WebClient.builder().build();
            SetCookie cookie = localAuthenticationCookie(provider, tenant, SID);
            HttpRouting.Builder routing = HttpRouting.builder();
            OidcFeature.create(provider).setup(routing);
            WebServer server = WebServer.builder().host("127.0.0.1").port(0).addRouting(routing).build().start();
            try {
                store.unavailable.set(true);
                URI uri = URI.create("http://127.0.0.1:" + server.port() + "/oidc/backchannel");
                assertThat(postLogout(client, uri, logoutToken(_ -> { })), is(Status.BAD_REQUEST_400));
                AuthenticationResponse response = authenticate(provider, cookie);
                assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                assertThat(response.statusCode().orElseThrow(), is(Status.SERVICE_UNAVAILABLE_503_CODE));
                assertThat(response.user().isEmpty(), is(true));
            } finally {
                server.stop();
                client.closeResource();
            }
        }
    }

    @Test
    void replayRecordOutlivesAcceptedLogoutTokenWhenBrowserLifetimeIsShorter() {
        TestStore store = new TestStore();
        OidcTenantConfig tenant = OidcTenantConfig.builder(withStore(store))
                .cookies(cookies -> cookies.password("test-cookie-password")
                        .localAuthenticationLifetime(Duration.ofSeconds(30)))
                .buildPrototype();
        try (OidcProvider provider = provider(tenant)) {
            WebClient client = WebClient.builder().build();
            HttpRouting.Builder routing = HttpRouting.builder();
            OidcFeature.create(provider).setup(routing);
            WebServer server = WebServer.builder().host("127.0.0.1").port(0).addRouting(routing).build().start();
            try {
                URI uri = URI.create("http://127.0.0.1:" + server.port() + "/oidc/backchannel");
                String token = logoutToken(builder -> builder.subject("alice")
                        .removePayloadClaim("sid")
                        .expirationTime(Instant.now().plusSeconds(180)));
                Instant expiresAt = SignedJwt.parseToken(token).getJwt().expirationTime().orElseThrow();

                Instant beforePost = Instant.now();
                assertThat(postLogout(client, uri, token), is(Status.OK_200));

                // A subject-only replay after a fresh login must not advance its generation a second time.
                assertThat(store.retainUntil.get().isBefore(expiresAt.plus(tenant.idToken().clockSkew())), is(false));
                // A pending authorization callback also needs its revocation marker until the state cookie expires.
                assertThat(store.retainUntil.get().isBefore(beforePost.plus(tenant.cookies()
                                                                           .authenticationRequestLifetime())), is(false));
            } finally {
                server.stop();
                client.closeResource();
            }
        }
    }

    private static Status postLogout(WebClient client, URI uri, String token) {
        try (HttpClientResponse response = client.post().uri(uri)
                .submit(Parameters.builder("logout").add("logout_token", token).build())) {
            return response.status();
        }
    }

    private static HttpClientResponse postRawLogout(WebClient client, URI uri, String contentType, String body) {
        HttpClientRequest request = client.post().uri(uri);
        if (contentType != null) {
            request.header(HeaderNames.CONTENT_TYPE, contentType);
        }
        return request.submit(body);
    }

    private static void assertBadLogoutResponse(HttpClientResponse response, String caseName) {
        assertThat(caseName, response.status(), is(Status.BAD_REQUEST_400));
        assertThat(caseName, response.headers().first(HeaderNames.CACHE_CONTROL).orElse(""), is("no-store"));
        assertThat(caseName, response.headers().contains(HeaderNames.SET_COOKIE), is(false));
        assertThat(caseName, response.entity().hasEntity(), is(false));
    }

    private static WebServer logoutServer(OidcProvider provider) {
        HttpRouting.Builder routing = HttpRouting.builder();
        OidcFeature.create(provider).setup(routing);
        return WebServer.builder().host("127.0.0.1").port(0).addRouting(routing).build().start();
    }

    private static SetCookie localAuthenticationCookie(OidcProvider provider, OidcTenantConfig tenant, String sid) {
        return localAuthenticationCookie(provider, tenant, sid, Instant.now().truncatedTo(ChronoUnit.SECONDS));
    }

    private static SetCookie localAuthenticationCookie(OidcProvider provider,
                                                       OidcTenantConfig tenant,
                                                       String sid,
                                                       Instant issuedAt) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        String token = SignedJwt.sign(Jwt.builder().algorithm("RS256").keyId("verify-rsa")
                                              .issuer(ISSUER).subject(SUBJECT).addAudience(CLIENT_ID)
                                              .issueTime(issuedAt).expirationTime(now.plusSeconds(3600))
                                              .addPayloadClaim("sid", sid).build(),
                                      signKeys.forKeyId("sign-rsa").orElseThrow()).tokenContent();
        SignedJwt signed = SignedJwt.parseToken(token);
        OidcLocalAuthenticationResult result = OidcLocalAuthenticationResult.fromStoredValues(
                OidcLocalAuthenticationState.builder()
                        .tenantId("default")
                        .idToken(new OidcValidatedIdToken(token, false, signed, signed.getJwt()))
                        .accessToken("opaque-access")
                        .tokenType("Bearer")
                        .refreshToken("opaque-refresh")
                        .scope("openid")
                        .createdAt(now)
                        .expiresAt(now.plusSeconds(3600))
                        .buildPrototype());
        OidcBackChannelLogoutStore store = provider.tenantRuntimeRegistry().logoutStore("default").orElseThrow();
        result = result.withBackChannelSession(OidcBackChannelSessionSupport.begin(
                result, store, store.authorizationCheckpoint("default", ISSUER), false));
        return OidcCookieStateHandler.create("default", tenant)
                .createLocalAuthenticationResultCookies(result, Map.of(), now).getFirst();
    }

    private static AuthenticationResponse authenticate(OidcProvider provider, SetCookie cookie) {
        return provider.authenticate(OidcProviderTest.request(null,
                SecurityEnvironment.builder().targetUri(URI.create("http://127.0.0.1/resource"))
                        .header(HeaderNames.COOKIE.defaultCase(), cookie.name() + "=" + cookie.value())
                        .build()));
    }

    private static String logoutToken(Consumer<Jwt.Builder> update) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Jwt.Builder builder = Jwt.builder().algorithm("RS256").keyId("verify-rsa")
                .type("logout+jwt").issuer(ISSUER).subject(SUBJECT).addAudience(CLIENT_ID)
                .issueTime(now).expirationTime(now.plusSeconds(120)).jwtId("logout-1")
                .addPayloadClaim("sid", SID)
                .addPayloadClaim("events", JsonObject.builder()
                        .set(EVENT, JsonObject.builder().build()).build());
        update.accept(builder);
        return SignedJwt.sign(builder.build(), signKeys.forKeyId("sign-rsa").orElseThrow()).tokenContent();
    }

    private static OidcTenantConfig tenant() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret("client-secret")
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(URI.create(ISSUER + "/authorize"))
                        .tokenEndpointUri(URI.create(ISSUER + "/token"))
                        .jwksUri(verificationUri)
                        .tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(URI.create("http://127.0.0.1/oidc/callback")))
                .logout(logout -> logout.backChannel(backChannel ->
                        backChannel.uri(URI.create("http://127.0.0.1/oidc/backchannel"))))
                .cookies(cookies -> cookies.password("test-cookie-password"))
                .buildPrototype();
    }

    private static OidcTenantConfig withStore(OidcBackChannelLogoutStore store) {
        return OidcTenantConfig.builder(tenant())
                .logout(logout -> logout.backChannel(backChannel -> backChannel
                        .uri(URI.create("http://127.0.0.1/oidc/backchannel")).store(store)))
                .buildPrototype();
    }

    private static OidcProvider provider(OidcTenantConfig tenant) {
        return OidcProvider.create(OidcProviderConfig.builder().putTenant("default", tenant).buildPrototype());
    }

    private static final class TestStore implements OidcBackChannelLogoutStore {
        private final OidcInMemoryLogoutStore delegate = new OidcInMemoryLogoutStore();
        private final AtomicBoolean unavailable = new AtomicBoolean();
        private final AtomicInteger revocations = new AtomicInteger();
        private final AtomicReference<Instant> retainUntil = new AtomicReference<>();

        @Override
        public String authorizationCheckpoint(String tenantId, String issuer) {
            requireAvailable();
            return delegate.authorizationCheckpoint(tenantId, issuer);
        }

        @Override
        public Optional<Marker> beginSession(Identity identity, String authorizationCheckpoint) {
            requireAvailable();
            return delegate.beginSession(identity, authorizationCheckpoint);
        }

        @Override
        public boolean revoked(Session session) {
            requireAvailable();
            return delegate.revoked(session);
        }

        @Override
        public void revoke(LogoutEvent event, Instant retainUntil) {
            requireAvailable();
            delegate.revoke(event, retainUntil);
            revocations.incrementAndGet();
            this.retainUntil.set(retainUntil);
        }

        private void requireAvailable() {
            if (unavailable.get()) {
                throw new IllegalStateException("Test store is unavailable");
            }
        }
    }
}
