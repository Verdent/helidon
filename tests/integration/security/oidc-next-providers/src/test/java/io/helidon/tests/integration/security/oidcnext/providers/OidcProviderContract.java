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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.providers.oidc.next.OidcAuthorizationCodeConfig;
import io.helidon.security.providers.oidc.next.OidcLogoutConfig;
import io.helidon.security.providers.oidc.next.OidcOutboundPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationConfig;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.DockerClientFactory;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasKey;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class OidcProviderContract {
    private IdpAdapter adapter;

    abstract IdpAdapter createAdapter();

    @BeforeAll
    void startProvider() throws Exception {
        assumeTrue(DockerClientFactory.instance().isDockerAvailable(), "Provider integration tests require Docker");
        adapter = createAdapter();
        try {
            adapter.start();
        } catch (Exception e) {
            try {
                adapter.close();
            } catch (RuntimeException closeFailure) {
                e.addSuppressed(closeFailure);
            }
            throw e;
        }
    }

    @AfterAll
    void stopProvider() {
        if (adapter != null) {
            adapter.close();
        }
    }

    @Test
    void discoveryIdentifiesTheConfiguredIssuerAndEndpoints() {
        WebClient client = WebClient.builder().from(adapter.webClient()).build();
        try (HttpClientResponse response = client.get()
                .uri(URI.create(adapter.issuer() + "/.well-known/openid-configuration")).request()) {
            assertThat(response.status(), is(Status.OK_200));
            JsonObject metadata = response.as(JsonObject.class);
            assertThat(metadata.stringValue("issuer").orElseThrow(), is(adapter.issuer().toString()));
            for (String endpoint : List.of("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri")) {
                assertThat(URI.create(metadata.stringValue(endpoint).orElseThrow()).getScheme(), is("https"));
            }
        } finally {
            client.closeResource();
        }
    }

    @Test
    void confidentialCodeFlowUsesPkceAndAuthenticatesTheUser() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.OK_200));
                assertThat(response.as(JsonObject.class).stringValue("name").orElseThrow(), is("alice"));
            }
        }
    }

    @Test
    void publicCodeFlowAuthenticatesWithS256WithoutAClientSecret() throws Exception {
        require(IdpAdapter.Capability.PUBLIC_CLIENT);
        assertBrowserAuthentication(IdpAdapter.ClientMode.PUBLIC);
    }

    @Test
    void clientSecretPostAuthenticatesAtTheTokenEndpoint() throws Exception {
        require(IdpAdapter.Capability.CLIENT_SECRET_POST);
        assertBrowserAuthentication(IdpAdapter.ClientMode.POST);
    }

    @Test
    void privateKeyJwtAuthenticatesAtTheTokenEndpoint() throws Exception {
        require(IdpAdapter.Capability.PRIVATE_KEY_JWT);
        assertBrowserAuthentication(IdpAdapter.ClientMode.PRIVATE_JWT);
    }

    @Test
    void clientSecretJwtAuthenticatesAtTheTokenEndpoint() throws Exception {
        require(IdpAdapter.Capability.CLIENT_SECRET_JWT);
        assertBrowserAuthentication(IdpAdapter.ClientMode.SECRET_JWT);
    }

    @Test
    void userInfoAndClaimMappingPreserveIdentityRolesAndScopes() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.OK_200));
                JsonObject claims = response.as(JsonObject.class);
                assertThat(claims.stringValue("name").orElseThrow(), is("alice"));
                assertThat(claims.stringValue("email").orElseThrow(), is("alice@example.org"));
                assertThat(claims.arrayValue("roles").orElseThrow().values().stream()
                                   .map(value -> value.asString().value()).toList(), hasItems("reader"));
                assertThat(claims.arrayValue("scopes").orElseThrow().values().stream()
                                   .map(value -> value.asString().value()).toList(), hasItems("resource.read"));
            }
        }
    }

    @Test
    void refreshRenewsTheCookieAndPreservesTheUserIdentity() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true, tenant -> {
            tenant.authorizationCode(OidcAuthorizationCodeConfig.builder().from(tenant.authorizationCode().orElseThrow())
                    .scopes(List.of("openid", "profile", "email", "groups", "resource.read", "offline_access"))
                    .buildPrototype());
            OidcTokenValidationConfig validation = tenant.protectedResource().orElseThrow().tokenValidation();
            tenant.protectedResource(resource -> resource.tokenValidation(OidcTokenValidationConfig.builder().from(validation)
                    .clockSkew(Duration.ofHours(2)).buildPrototype()));
        }); TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.OK_200));
                assertThat(response.as(JsonObject.class).stringValue("name").orElseThrow(), is("alice"));
                assertThat(response.headers().contains(HeaderNames.SET_COOKIE), is(true));
            }
        }
    }

    @Test
    void localLogoutClearsTheAuthenticationCookie() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.post(rp.baseUri().resolve("/oidc/logout"), Parameters.empty("logout"))) {
                assertThat(response.status(), is(Status.NO_CONTENT_204));
                assertThat(response.headers().contains(HeaderNames.SET_COOKIE), is(true));
            }
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
            }
        }
    }

    @Test
    void tamperedCallbackStateIsRejectedBeforeCodeRedemption() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            URI authorization = authorization(browser, rp);
            URI callback = adapter.login(browser, authorization, rp.baseUri().resolve("/oidc/callback"));
            Map<String, String> query = new LinkedHashMap<>();
            UriQuery callbackQuery = UriQuery.create(callback);
            callbackQuery.names().forEach(name -> query.put(name, callbackQuery.first(name).orElseThrow()));
            query.put("state", "tampered-state");
            URI tampered = URI.create(callback.getScheme() + "://" + callback.getAuthority()
                                              + callback.getPath() + "?" + query(query));
            try (HttpClientResponse response = browser.get(tampered)) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
            }
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
            }
        }
    }

    @Test
    void consumedAuthorizationCallbackCannotBeReplayed() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            URI callback = authenticate(browser, rp);
            try (HttpClientResponse response = browser.get(callback)) {
                assertThat(response.status(), is(Status.BAD_REQUEST_400));
            }
        }
    }

    @Test
    void apiRejectsMissingAndUnknownBearerCredentials() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, false, _ -> { })) {
            assertApi(rp, null, Status.UNAUTHORIZED_401);
            assertApi(rp, "not-issued-by-this-provider", Status.UNAUTHORIZED_401);
        }
    }

    @Test
    void introspectionAuthenticatesAUserAccessToken() throws Exception {
        String token = userTokens(IdpAdapter.ClientMode.BASIC).stringValue("access_token").orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, false, _ -> { })) {
            JsonObject claims = assertApi(rp, token, Status.OK_200);
            assertThat(claims.stringValue("name").orElseThrow(), is("alice"));
        }
    }

    @Test
    void introspectionRejectsAValidTokenForADifferentAudience() throws Exception {
        String token = userTokens(IdpAdapter.ClientMode.BASIC).stringValue("access_token").orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, false,
                tenant -> changeAudience(tenant, "different-resource"))) {
            assertApi(rp, token, Status.UNAUTHORIZED_401);
        }
    }

    @Test
    void clientCredentialsObtainsAnAccessTokenAndIntrospectionAcceptsIt() throws Exception {
        JsonObject tokenResponse = clientCredentials();
        assertThat(tokenResponse.stringValue("token_type").orElseThrow().toLowerCase(Locale.ROOT), is("bearer"));
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.SERVICE, false, _ -> { })) {
            assertApi(rp, tokenResponse.stringValue("access_token").orElseThrow(), Status.OK_200);
        }
    }

    @Test
    void jwtValidationAcceptsTheProvidersSupportedTokenLayout() throws Exception {
        require(IdpAdapter.Capability.JWT_ACCESS_TOKEN);
        String token = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("access_token").orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false, _ -> { })) {
            assertThat(assertApi(rp, token, Status.OK_200).stringValue("name").orElseThrow(), is("alice"));
        }
    }

    @Test
    void jwtValidationRejectsTamperedSignatures() throws Exception {
        require(IdpAdapter.Capability.JWT_ACCESS_TOKEN);
        String token = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("access_token").orElseThrow();
        int signature = token.lastIndexOf('.') + 1;
        String tampered = token.substring(0, signature) + (token.charAt(signature) == 'A' ? 'B' : 'A')
                + token.substring(signature + 1);
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false, _ -> { })) {
            assertApi(rp, tampered, Status.UNAUTHORIZED_401);
        }
    }

    @Test
    void jwtValidationRejectsAnIdTokenEvenWhenItsAudienceMatches() throws Exception {
        require(IdpAdapter.Capability.JWT_ACCESS_TOKEN);
        String idToken = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("id_token").orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false,
                tenant -> changeAudience(tenant, IdpAdapter.ClientMode.JWT_ACCESS.id()))) {
            assertApi(rp, idToken, Status.UNAUTHORIZED_401);
        }
    }

    @Test
    void pushedAuthorizationRequestCompletesTheBrowserLogin() throws Exception {
        require(IdpAdapter.Capability.PAR);
        assertBrowserAuthentication(IdpAdapter.ClientMode.PAR);
    }

    @Test
    void signedRequestObjectCompletesTheBrowserLogin() throws Exception {
        require(IdpAdapter.Capability.JAR);
        assertBrowserAuthentication(IdpAdapter.ClientMode.JAR);
    }

    @Test
    void signedUserInfoCompletesTheBrowserLogin() throws Exception {
        require(IdpAdapter.Capability.SIGNED_USERINFO);
        assertBrowserAuthentication(IdpAdapter.ClientMode.SIGNED_USERINFO);
    }

    @Test
    void encryptedIdTokenCompletesTheBrowserLogin() throws Exception {
        require(IdpAdapter.Capability.ENCRYPTED_ID_TOKEN);
        assertBrowserAuthentication(IdpAdapter.ClientMode.ENCRYPTED_ID_TOKEN);
    }

    @Test
    void rpInitiatedLogoutCompletesAtTheProviderAndClearsTheLocalSession() throws Exception {
        require(IdpAdapter.Capability.RP_LOGOUT);
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true,
                tenant -> tenant.logout(OidcLogoutConfig.builder().endSession(end -> end.enabled(true)).buildPrototype()));
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.post(rp.baseUri().resolve("/oidc/logout"), Parameters.empty("logout"))) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
                URI endSession = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                assertThat(UriQuery.create(endSession).contains("id_token_hint"), is(true));
                try (HttpClientResponse providerResponse = browser.get(endSession)) {
                    assertThat(providerResponse.status(), is(Status.OK_200));
                }
            }
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
            }
        }
    }

    @Test
    void outboundTokenPropagationPreservesTheValidatedAccessToken() throws Exception {
        assertOutbound(OidcOutboundPolicyConfig.builder().tokenPropagationEnabled(true)
                .audience(IdpAdapter.AUDIENCE).buildPrototype(), true, false);
    }

    @Test
    void outboundClientCredentialsAcquiresAndCachesItsOwnAccessToken() throws Exception {
        assertOutbound(OidcOutboundPolicyConfig.builder().clientCredentialsGrantEnabled(true)
                .clientCredentialsScopes(List.of("resource.read")).buildPrototype(), false, true);
    }

    @Test
    void outboundTokenExchangeObtainsATokenForTheTargetAudience() throws Exception {
        require(IdpAdapter.Capability.TOKEN_EXCHANGE);
        assertOutbound(OidcOutboundPolicyConfig.builder().tokenExchangeEnabled(true)
                .tokenExchangeAudience(IdpAdapter.AUDIENCE).tokenExchangeScopes(List.of("resource.read"))
                .buildPrototype(), false, false);
    }

    private void assertOutbound(OidcOutboundPolicyConfig policy, boolean propagation, boolean checkCache) throws Exception {
        String inbound = userTokens(IdpAdapter.ClientMode.BASIC).stringValue("access_token").orElseThrow();
        AtomicReference<String> received = new AtomicReference<>();
        WebServer downstream = WebServer.builder().host("127.0.0.1").port(0).tls(IdpResources.serverTls())
                .routing(routing -> routing.get("/downstream", (request, response) -> {
                    received.set(request.headers().first(HeaderNames.AUTHORIZATION).orElseThrow());
                    response.send("downstream");
                })).build().start();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.SERVICE,
                URI.create("https://localhost:" + downstream.port() + "/downstream"), policy)) {
            WebClient client = WebClient.builder().from(adapter.webClient()).build();
            try {
                try (HttpClientResponse response = client.get().uri(rp.baseUri().resolve("/proxy"))
                        .header(HeaderNames.AUTHORIZATION, "Bearer " + inbound).request()) {
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.as(String.class), is("downstream"));
                }
                String first = received.get();
                if (propagation) {
                    assertThat(first, is("Bearer " + inbound));
                } else {
                    assertThat(first, not("Bearer " + inbound));
                    assertThat(first, startsWith("Bearer "));
                    assertApi(rp, first.substring("Bearer ".length()), Status.OK_200);
                }
                if (checkCache) {
                    try (HttpClientResponse response = client.get().uri(rp.baseUri().resolve("/proxy"))
                            .header(HeaderNames.AUTHORIZATION, "Bearer " + inbound).request()) {
                        assertThat(response.status(), is(Status.OK_200));
                    }
                    assertThat(received.get(), is(first));
                }
            } finally {
                client.closeResource();
            }
        } finally {
            downstream.stop();
        }
    }

    private void require(IdpAdapter.Capability capability) {
        if (!adapter.capabilities().contains(capability)) {
            assumeTrue(false, adapter.unavailableReason(capability));
        }
    }

    void assertNonconformingSignedUserInfoIsRejected() throws Exception {
        String accessToken = userTokens(IdpAdapter.ClientMode.SIGNED_USERINFO).stringValue("access_token").orElseThrow();
        WebClient client = WebClient.builder().from(adapter.webClient()).build();
        try (HttpClientResponse response = client.get()
                .uri(URI.create(metadata().stringValue("userinfo_endpoint").orElseThrow()))
                .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken).request()) {
            assertThat(response.status(), is(Status.OK_200));
            assertThat(response.headers().first(HeaderNames.CONTENT_TYPE).orElseThrow(), startsWith("application/jwt"));
            var jwt = SignedJwt.parseToken(response.as(String.class)).getJwt();
            assertThat(jwt.algorithm().orElseThrow(), is("RS256"));
            assertThat(jwt.payloadClaimsJson(), not(hasKey("iss")));
            assertThat(jwt.payloadClaimsJson(), not(hasKey("aud")));
            assertThat(jwt.subject().orElseThrow(), not(""));
        } finally {
            client.closeResource();
        }
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.SIGNED_USERINFO, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            URI callback = adapter.login(browser, authorization(browser, rp), rp.baseUri().resolve("/oidc/callback"));
            try (HttpClientResponse response = browser.get(callback)) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("UserInfo response is invalid"));
            }
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
            }
        }
    }

    private void assertBrowserAuthentication(IdpAdapter.ClientMode mode) throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, mode, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.OK_200));
                assertThat(response.as(JsonObject.class).stringValue("name").orElseThrow(), is("alice"));
            }
        }
    }

    private JsonObject userTokens(IdpAdapter.ClientMode mode) throws Exception {
        String verifier = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        Map<String, String> request = new LinkedHashMap<>();
        request.put("client_id", mode.id());
        request.put("response_type", "code");
        request.put("redirect_uri", IdpAdapter.COLLECTOR);
        request.put("scope", "openid profile email groups resource.read");
        request.put("state", UUID.randomUUID().toString());
        request.put("nonce", UUID.randomUUID().toString());
        request.put("code_challenge", challenge);
        request.put("code_challenge_method", "S256");
        URI authorize = URI.create(metadata().stringValue("authorization_endpoint").orElseThrow() + "?" + query(request));
        URI callback;
        try (TestBrowser browser = new TestBrowser(adapter.webClient())) {
            callback = adapter.login(browser, authorize, URI.create(IdpAdapter.COLLECTOR));
        }
        assertThat(UriQuery.create(callback).first("state").orElseThrow(), is(request.get("state")));
        Parameters form = Parameters.builder("token").add("grant_type", "authorization_code")
                .add("code", UriQuery.create(callback).first("code").orElseThrow())
                .add("redirect_uri", IdpAdapter.COLLECTOR).add("code_verifier", verifier).build();
        return tokenRequest(mode, form);
    }

    private JsonObject clientCredentials() {
        return tokenRequest(IdpAdapter.ClientMode.SERVICE,
                Parameters.builder("token").add("grant_type", "client_credentials").add("scope", "resource.read").build());
    }

    private JsonObject tokenRequest(IdpAdapter.ClientMode mode, Parameters form) {
        WebClient client = WebClient.builder().from(adapter.webClient()).build();
        String basic = Base64.getEncoder().encodeToString((mode.id() + ":" + IdpAdapter.SECRET).getBytes(StandardCharsets.UTF_8));
        try (HttpClientResponse response = client.post().uri(URI.create(metadata().stringValue("token_endpoint").orElseThrow()))
                .header(HeaderNames.AUTHORIZATION, "Basic " + basic).submit(form)) {
            assertThat(response.status(), is(Status.OK_200));
            return response.as(JsonObject.class);
        } finally {
            client.closeResource();
        }
    }

    private JsonObject metadata() {
        WebClient client = WebClient.builder().from(adapter.webClient()).build();
        try (HttpClientResponse response = client.get().uri(URI.create(adapter.issuer() + "/.well-known/openid-configuration"))
                .request()) {
            assertThat(response.status(), is(Status.OK_200));
            return response.as(JsonObject.class);
        } finally {
            client.closeResource();
        }
    }

    private JsonObject assertApi(RelyingParty rp, String token, Status expected) {
        WebClient client = WebClient.builder().from(adapter.webClient()).build();
        try {
            var request = client.get().uri(rp.baseUri().resolve("/api"));
            if (token != null) {
                request.header(HeaderNames.AUTHORIZATION, "Bearer " + token);
            }
            try (HttpClientResponse response = request.request()) {
                assertThat(response.status(), is(expected));
                if (expected == Status.OK_200) {
                    return response.as(JsonObject.class);
                }
                return JsonObject.builder().build();
            }
        } finally {
            client.closeResource();
        }
    }

    private static void changeAudience(OidcTenantConfig.Builder tenant, String audience) {
        OidcTokenValidationConfig validation = tenant.protectedResource().orElseThrow().tokenValidation();
        tenant.protectedResource(resource -> resource.tokenValidation(OidcTokenValidationConfig.builder().from(validation)
                .audience(audience).buildPrototype()));
    }

    private static String query(Map<String, String> parameters) {
        return parameters.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));
    }

    private URI authorization(TestBrowser browser, RelyingParty rp) throws Exception {
        try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
            String detail = response.status().equals(Status.SEE_OTHER_303)
                    ? "successful redirect" : response.entity().asOptional(String.class).orElse("empty response");
            assertThat("Authorization response: " + detail, response.status(), is(Status.SEE_OTHER_303));
            URI uri = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
            UriQuery query = UriQuery.create(uri);
            if (!query.contains("request") && !query.contains("request_uri")) {
                assertThat(query.first("code_challenge_method").orElseThrow(), is("S256"));
                assertThat(query.first("code_challenge").orElseThrow().length(), is(43));
            }
            return uri;
        }
    }

    private URI authenticate(TestBrowser browser, RelyingParty rp) throws Exception {
        URI authorization = authorization(browser, rp);
        URI callback = adapter.login(browser, authorization, rp.baseUri().resolve("/oidc/callback"));
        if (UriQuery.create(callback).contains("error")) {
            throw new IllegalStateException("Provider authorization error: " + callback);
        }
        try (HttpClientResponse response = browser.get(callback)) {
            String detail = response.status().equals(Status.SEE_OTHER_303)
                    ? "successful redirect" : response.entity().asOptional(String.class).orElse("empty response");
            String diagnostics = response.status().equals(Status.SEE_OTHER_303) ? "" : "\n" + adapter.diagnostics();
            assertThat("Callback response: " + detail + diagnostics,
                       response.status(), is(Status.SEE_OTHER_303));
        }
        return callback;
    }
}
