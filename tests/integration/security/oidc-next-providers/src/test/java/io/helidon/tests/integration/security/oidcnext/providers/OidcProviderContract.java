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
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.Method;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.providers.oidc.next.OidcAuthorizationCodeConfig;
import io.helidon.security.providers.oidc.next.OidcCookieConfig;
import io.helidon.security.providers.oidc.next.OidcJwtAccessTokenConfig;
import io.helidon.security.providers.oidc.next.OidcLogoutConfig;
import io.helidon.security.providers.oidc.next.OidcOutboundPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcOutboundStrategy;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.DockerClientFactory;

import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class OidcProviderContract {
    private IdpAdapter adapter;

    abstract IdpAdapter createAdapter();

    final IdpAdapter adapter() {
        return adapter;
    }

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

    // OIDC Discovery 1.0 §4.3 (https://openid.net/specs/openid-connect-discovery-1_0.html):
    // "The `issuer` value returned MUST be identical to the Issuer URL". This also checks
    // real OP metadata, not the separate RP logic for rejecting a mismatched discovery response.
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

    // RFC 9700 §2.1.1 (https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1):
    // for confidential clients, PKCE "is RECOMMENDED, as it provides strong protection against misuse
    // and injection of authorization codes". The shared browser helper asserts S256 on the request.
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

    // RFC 9700 §2.1.1: "Public clients MUST use PKCE". The OP enforces S256 and
    // the RP does not possess a client secret for this public-client registration.
    @Test
    void publicCodeFlowAuthenticatesWithS256WithoutAClientSecret() throws Exception {
        require(IdpAdapter.Capability.PUBLIC_CLIENT);
        assertBrowserAuthentication(IdpAdapter.ClientMode.PUBLIC);
    }

    @Test
    void clientSecretPostAuthenticatesAtTheTokenEndpoint() throws Exception {
        // RFC 6749, 2.3.1: "the authorization server MAY support including the client credentials in the request-body"
        // https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
        // The Keycloak client fixture permits only client_secret_post, so Basic cannot make this test pass.
        require(IdpAdapter.Capability.CLIENT_SECRET_POST);
        assertBrowserAuthentication(IdpAdapter.ClientMode.POST);
    }

    // RFC 7523 §2.2 (https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2):
    // "The value of the \"client_assertion\" parameter contains a single JWT."
    // The real OP requires private-key JWT authentication for this client registration.
    @Test
    void privateKeyJwtAuthenticatesAtTheTokenEndpoint() throws Exception {
        require(IdpAdapter.Capability.PRIVATE_KEY_JWT);
        assertBrowserAuthentication(IdpAdapter.ClientMode.PRIVATE_JWT);
    }

    // RFC 7523 §2.2: "The value of the \"client_assertion\" parameter contains a single JWT."
    // This fixture selects client_secret_jwt instead of private_key_jwt for the registered client.
    @Test
    void clientSecretJwtAuthenticatesAtTheTokenEndpoint() throws Exception {
        require(IdpAdapter.Capability.CLIENT_SECRET_JWT);
        assertBrowserAuthentication(IdpAdapter.ClientMode.SECRET_JWT);
    }

    /*
     * Spec: OpenID Connect Core 1.0, 5.3.2, Successful UserInfo Response.
     * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
     * Quote: "The `sub` Claim in the UserInfo Response MUST be verified to exactly match the `sub` Claim in the ID Token"
     */
    @Test
    void userInfoAndClaimMappingPreserveIdentityRolesAndScopes() throws Exception {
        URI endpoint = URI.create(metadata().stringValue("userinfo_endpoint").orElseThrow());
        try (UserInfoRecorder recorder = new UserInfoRecorder(adapter, endpoint);
             RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true,
                     tenant -> tenant.endpoints(endpoints -> endpoints.userInfoEndpointUri(recorder.uri())));
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.OK_200));
                JsonObject subject = response.as(JsonObject.class);
                assertMappedUserSubject(subject);
                assertUserInfoSubjectMatches(subject, recordedUserInfoSubject(recorder, false));
            }
        }
    }

    // Roles are application policy mapped from provider claims; OIDC does not mandate
    // the Helidon role names "reader" and "admin" or the authorization outcome.
    @Test
    void mappedRolesAllowReaderAccessAndRejectAdminAccess() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/roles/reader"))) {
                assertThat(response.status(), is(Status.OK_200));
                assertThat(response.as(JsonObject.class).stringValue("name").orElseThrow(), is("alice"));
            }
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/roles/admin"))) {
                assertThat(response.status(), is(Status.FORBIDDEN_403));
            }
        }
    }

    // OAuth scope syntax is defined by RFC 6749 §3.3; the resource.read/resource.write
    // authorization rules here are application-specific, not built-in protocol semantics.
    @Test
    void grantedScopesAllowReadAccessAndRejectWriteAccess() throws Exception {
        String accessToken = userTokens(IdpAdapter.ClientMode.BASIC).stringValue("access_token").orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, false, _ -> { })) {
            assertResource(rp, "/api", accessToken, Status.OK_200);
            assertResource(rp, "/scopes/read", accessToken, Status.OK_200);
            assertResource(rp, "/scopes/write", accessToken, Status.FORBIDDEN_403);
        }
    }

    // OIDC Core 1.0 §12.2 (https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse):
    // if an ID Token is refreshed, "its `sub` Claim Value MUST be the same as in the ID Token issued
    // when the original authentication occurred". This tests a real refresh exchange and the RP's
    // local cookie renewal; cookie re-encryption itself is a Helidon implementation detail.
    @Test
    void refreshRenewsTheCookieAndPreservesTheUserIdentity() throws Exception {
        URI tokenEndpoint = URI.create(metadata().stringValue("token_endpoint").orElseThrow());
        try (OidcEndpointRecorder recorder = new OidcEndpointRecorder(adapter, tokenEndpoint);
             RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.SHORT_LIVED, true,
                     tenant -> configureRefresh(tenant, recorder.uri()));
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            assertThat(recorder.exchanges().stream().map(OidcEndpointRecorder.Exchange::grantType).toList(),
                       contains("authorization_code"));
            JsonObject initial = recorder.exchanges().getFirst().response();
            String cookieName = OidcCookieConfig.create().localAuthenticationCookieName();
            String originalCookie = browser.cookieValue(cookieName).orElseThrow();
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.OK_200));
                JsonObject subject = response.as(JsonObject.class);
                assertThat(subject.stringValue("name").orElseThrow(), is("alice"));
                assertThat(recorder.exchanges().stream().map(OidcEndpointRecorder.Exchange::grantType).toList(),
                           contains("authorization_code", "refresh_token"));
                OidcEndpointRecorder.Exchange refreshed = recorder.exchanges().getLast();
                assertThat(refreshed.status(), is(Status.OK_200));
                String accessToken = refreshed.response().stringValue("access_token").orElseThrow();
                assertThat(accessToken, not(initial.stringValue("access_token").orElseThrow()));
                assertThat(subject.stringValue("access_token").orElseThrow(), is(accessToken));
                // A separate client sends only the new Bearer token; the browser cookie cannot authenticate this request.
                JsonObject apiSubject = assertApi(rp, accessToken, Status.OK_200);
                assertThat(apiSubject.stringValue("id"), is(subject.stringValue("id")));
                assertThat(apiSubject.stringValue("name"), is(subject.stringValue("name")));
                assertThat(subject.arrayValue("scopes").orElseThrow().values().stream()
                                   .map(value -> value.asString().value()).toList(),
                           is(Arrays.stream(initial.stringValue("scope").orElseThrow().split(" ")).sorted().toList()));
                refreshed.response().stringValue("id_token").ifPresent(idToken ->
                        assertThat(SignedJwt.parseToken(idToken).getJwt().subject(),
                                   is(SignedJwt.parseToken(initial.stringValue("id_token").orElseThrow()).getJwt().subject())));
                assertThat(response.headers().first(HeaderNames.SET_COOKIE), not(Optional.empty()));
                assertThat(browser.cookieValue(cookieName).orElseThrow(), not(originalCookie));
            }
        }
    }

    // RFC 7009 §2.1 (https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1):
    // "the token cannot be used again after the revocation." The OP's invalid_grant response
    // prevents local refresh; redirect and cookie disposal are Helidon session behavior.
    @Test
    void revokedRefreshTokenCannotRenewTheLocalSession() throws Exception {
        require(IdpAdapter.Capability.REFRESH_TOKEN_REVOCATION);
        URI tokenEndpoint = URI.create(metadata().stringValue("token_endpoint").orElseThrow());
        try (OidcEndpointRecorder recorder = new OidcEndpointRecorder(adapter, tokenEndpoint);
             RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.SHORT_LIVED, true,
                     tenant -> configureRefresh(tenant, recorder.uri()));
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            String refreshToken = recorder.exchanges().getFirst().response().stringValue("refresh_token").orElseThrow();
            revokeToken(IdpAdapter.ClientMode.SHORT_LIVED, refreshToken, "refresh_token");
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(recorder.diagnostics() + "; last error: "
                                   + recorder.exchanges().getLast().response().stringValue("error"),
                           response.status(), is(Status.SEE_OTHER_303));
            }
            assertThat(recorder.exchanges().stream().map(OidcEndpointRecorder.Exchange::grantType).toList(),
                       contains("authorization_code", "refresh_token"));
            OidcEndpointRecorder.Exchange rejected = recorder.exchanges().getLast();
            assertThat(rejected.status(), is(Status.BAD_REQUEST_400));
            assertThat(rejected.response().stringValue("error").orElseThrow(), is("invalid_grant"));
            assertThat(browser.cookieValue(OidcCookieConfig.create().localAuthenticationCookieName()), is(Optional.empty()));
        }
    }

    // Local /oidc/logout clears only this RP's browser cookie; this is not evidence that
    // the OP session terminated under the separate RP-Initiated Logout specification.
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

    // RFC 6749 §10.12 (https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12):
    // "The client MUST implement CSRF protection for its redirection URI." Altered state
    // must not redeem an otherwise valid code from the real provider.
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

    // RFC 9700 §2.1.1: "the PKCE challenge or OpenID Connect `nonce` MUST be transaction-specific".
    // Rejecting an already consumed callback is Helidon's one-time state-cookie policy.
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

    // RFC 6749 §10.12: "The client MUST implement CSRF protection for its redirection URI."
    // A callback cannot be bound to a different browser without its original state cookie.
    @Test
    void callbackWithoutTheOriginalStateCookieDoesNotCreateASession() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true, _ -> { });
             TestBrowser original = new TestBrowser(adapter.webClient());
             TestBrowser unrelated = new TestBrowser(adapter.webClient())) {
            URI callback = adapter.login(original, authorization(original, rp), rp.baseUri().resolve("/oidc/callback"));
            assertRejectedCallback(unrelated, rp, callback, Status.BAD_REQUEST_400);
        }
    }

    // OIDC Core 1.0 §2 (https://openid.net/specs/openid-connect-core-1_0.html#IDToken):
    // "Clients MUST verify that the `nonce` Claim Value is equal to the value of the `nonce` parameter"
    // sent in the Authentication Request. The OP signs a real token with the changed nonce here.
    @Test
    void providerSignedIdTokenWithTheWrongNonceDoesNotCreateASession() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            URI changed = withQueryParameter(authorization(browser, rp), "nonce", "different-request-nonce-value");
            URI callback = adapter.login(browser, changed, rp.baseUri().resolve("/oidc/callback"));
            assertRejectedCallback(browser, rp, callback, Status.BAD_GATEWAY_502);
        }
    }

    // RFC 6749 §3.2.1: "Confidential clients or other clients issued client credentials MUST
    // authenticate with the authorization server". The OP rejects the deliberately wrong secret.
    @Test
    void rejectedClientAuthenticationDoesNotCreateASession() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true,
                tenant -> tenant.clientSecret("incorrect-client-secret-with-at-least-32-bytes"));
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            URI callback = adapter.login(browser, authorization(browser, rp), rp.baseUri().resolve("/oidc/callback"));
            assertRejectedCallback(browser, rp, callback, Status.BAD_GATEWAY_502);
        }
    }

    // RFC 6750 §3 (https://www.rfc-editor.org/rfc/rfc6750.html#section-3):
    // "If the protected resource request does not include authentication credentials" the
    // resource server must challenge it. This test checks status, not the WWW-Authenticate header.
    @Test
    void apiRejectsMissingAndUnknownBearerCredentials() throws Exception {
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, false, _ -> { })) {
            assertApi(rp, null, Status.UNAUTHORIZED_401);
            assertApi(rp, "not-issued-by-this-provider", Status.UNAUTHORIZED_401);
        }
    }

    // RFC 7662 §2.2 (https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2):
    // active is "REQUIRED. Boolean indicator of whether or not the presented token is currently active."
    // The native OP validates this token; the RP maps its returned identity.
    @Test
    void introspectionAuthenticatesAUserAccessToken() throws Exception {
        String token = userTokens(IdpAdapter.ClientMode.BASIC).stringValue("access_token").orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, false, _ -> { })) {
            JsonObject claims = assertApi(rp, token, Status.OK_200);
            assertThat(claims.stringValue("name").orElseThrow(), is("alice"));
        }
    }

    // RFC 9700 §2.3 (https://www.rfc-editor.org/rfc/rfc9700.html#section-2.3):
    // "If it was not, the resource server MUST refuse to serve the respective request."
    // The same token is accepted for the correct audience first, isolating the mismatch.
    @Test
    void introspectionRejectsAValidTokenForADifferentAudience() throws Exception {
        String token = userTokens(IdpAdapter.ClientMode.BASIC).stringValue("access_token").orElseThrow();
        // Control: this exact native token authenticates when the resource audience is correct.
        try (RelyingParty valid = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, false, _ -> { })) {
            assertApi(valid, token, Status.OK_200);
        }
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, false,
                tenant -> changeAudience(tenant, "different-resource"))) {
            assertApi(rp, token, Status.UNAUTHORIZED_401);
        }
    }

    // RFC 7662 §4 (https://www.rfc-editor.org/rfc/rfc7662.html#section-4):
    // "the authorization server MUST determine whether or not such a revocation has taken place."
    // This tests a real OP revocation followed by a fresh RP introspection decision.
    @Test
    void introspectionRejectsAnAccessTokenAfterNativeRevocation() throws Exception {
        require(IdpAdapter.Capability.ACCESS_TOKEN_REVOCATION);
        String accessToken = userTokens(IdpAdapter.ClientMode.BASIC).stringValue("access_token").orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, false, _ -> { })) {
            assertApi(rp, accessToken, Status.OK_200);
            revokeToken(IdpAdapter.ClientMode.BASIC, accessToken, "access_token");
            assertApi(rp, accessToken, Status.UNAUTHORIZED_401);
        }
    }

    // RFC 6749 §4.4.3 (https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.3):
    // "the authorization server issues an access token" for an authorized client-credentials request.
    // The real OP's introspection also accepts the resulting service token.
    @Test
    void clientCredentialsObtainsAnAccessTokenAndIntrospectionAcceptsIt() throws Exception {
        JsonObject tokenResponse = clientCredentials();
        assertThat(tokenResponse.stringValue("token_type").orElseThrow().toLowerCase(Locale.ROOT), is("bearer"));
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.SERVICE, false, _ -> { })) {
            assertApi(rp, tokenResponse.stringValue("access_token").orElseThrow(), Status.OK_200);
        }
    }

    // RFC 9068 §4 (https://www.rfc-editor.org/rfc/rfc9068.html#section-4):
    // "The resource server MUST verify that the \"typ\" header value is \"at+jwt\" or \"application/at+jwt\""
    // only for the RFC 9068 profile. Some native OP layouts here use a separately configured
    // CUSTOM profile; accepting such a token is not proof it conforms to RFC 9068.
    @Test
    void jwtValidationAcceptsTheProvidersSupportedTokenLayout() throws Exception {
        require(IdpAdapter.Capability.JWT_ACCESS_TOKEN);
        String token = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("access_token").orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false, _ -> { })) {
            assertThat(assertApi(rp, token, Status.OK_200).stringValue("name").orElseThrow(), is("alice"));
        }
    }

    // RFC 9700 §2.3: "If it was not, the resource server MUST refuse to serve the respective request."
    // The same native token first authenticates with the correct resource-audience setting.
    @Test
    void jwtValidationRejectsAValidTokenForADifferentAudience() throws Exception {
        require(IdpAdapter.Capability.JWT_ACCESS_TOKEN);
        String accessToken = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("access_token").orElseThrow();
        try (RelyingParty valid = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false, _ -> { })) {
            assertApi(valid, accessToken, Status.OK_200);
        }
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false,
                tenant -> changeAudience(tenant, "different-resource"))) {
            assertApi(rp, accessToken, Status.UNAUTHORIZED_401);
        }
    }

    // OIDC Core 1.0 §5.7 (https://openid.net/specs/openid-connect-core-1_0.html):
    // "the only guaranteed unique identifier for a given End-User is the combination of the `iss` Claim
    // and the `sub` Claim." Equal Helidon IDs across validation strategies are a local mapping invariant.
    @Test
    void jwtAndIntrospectionProduceTheSameIdentityForTheSameNativeToken() throws Exception {
        require(IdpAdapter.Capability.JWT_ACCESS_TOKEN);
        String accessToken = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("access_token").orElseThrow();
        try (RelyingParty jwt = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false, _ -> { });
             RelyingParty introspection = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false, tenant -> {
                 OidcTokenValidationConfig original = tenant.protectedResource().orElseThrow().tokenValidation();
                 tenant.protectedResource(resource -> resource.tokenValidation(OidcTokenValidationConfig.builder().from(original)
                         .method(OidcTokenValidationMethod.INTROSPECTION).jwt(OidcJwtAccessTokenConfig.create())
                         .buildPrototype()));
             })) {
            assertThat(assertApi(jwt, accessToken, Status.OK_200).stringValue("id").orElseThrow(),
                       is(assertApi(introspection, accessToken, Status.OK_200).stringValue("id").orElseThrow()));
        }
    }

    // RFC 6749 §4.4.2: client-credentials grant_type is "REQUIRED. Value MUST be set to \"client_credentials\"."
    // The scope string and principal mapping are provider/application-specific.
    @Test
    void jwtValidationAcceptsANativeClientCredentialsToken() throws Exception {
        require(IdpAdapter.Capability.JWT_CLIENT_CREDENTIALS);
        String accessToken = tokenRequest(IdpAdapter.ClientMode.JWT_SERVICE,
                Parameters.builder("token").add("grant_type", "client_credentials").add("scope", "resource.read").build())
                .stringValue("access_token").orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_SERVICE, false, _ -> { })) {
            JsonObject subject = assertApi(rp, accessToken, Status.OK_200);
            assertThat("Native token claims: " + SignedJwt.parseToken(accessToken).getJwt().payloadClaimsJson(),
                       subject.arrayValue("scopes").orElseThrow().values().stream()
                               .map(value -> value.asString().value()).toList(), hasItems("resource.read"));
        }
    }

    // OIDC Core 1.0 §10.1 (https://openid.net/specs/openid-connect-core-1_0.html#Signing):
    // "If there are multiple keys in the referenced JWK Set document, a `kid` value MUST be provided".
    // The timing of JWKS re-fetch and retention of the previous key are Helidon cache policy.
    @Test
    void cachedJwksAcceptsTheRotatedSigningKeyAndRetainsThePreviousKey() throws Exception {
        require(IdpAdapter.Capability.SIGNING_KEY_ROTATION);
        require(IdpAdapter.Capability.JWT_ACCESS_TOKEN);
        URI jwks = URI.create(metadata().stringValue("jwks_uri").orElseThrow());
        AtomicInteger loads = new AtomicInteger();
        String original = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("access_token").orElseThrow();
        String previousKeyId = SignedJwt.parseToken(original).getJwt().keyId().orElseThrow();
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false, tenant -> tenant
                .jwkSet(keys -> keys.unknownKeyIdRefreshInterval(Duration.ZERO))
                .webClient(WebClientConfig.builder().from(adapter.webClient()).addService((chain, request) -> {
                    if (request.method().equals(Method.GET) && request.uri().toUri().equals(jwks)) {
                        loads.incrementAndGet();
                    }
                    return chain.proceed(request);
                }).buildPrototype()))) {
            JsonObject originalSubject = assertApi(rp, original, Status.OK_200);
            assertThat(loads.get(), is(1));
            try (AutoCloseable _ = adapter.rotateSigningKey()) {
                String rotated = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("access_token").orElseThrow();
                assertThat(SignedJwt.parseToken(rotated).getJwt().keyId().orElseThrow(), not(previousKeyId));
                assertThat(assertApi(rp, rotated, Status.OK_200).stringValue("id"), is(originalSubject.stringValue("id")));
                assertThat(loads.get(), is(2));
                assertApi(rp, original, Status.OK_200);
                assertThat(loads.get(), is(2));
            }
        }
    }

    // RFC 7515 §5.2 (https://www.rfc-editor.org/rfc/rfc7515.html#section-5.2):
    // "at least one JWS Signature value MUST successfully validate". The unmodified native
    // token first succeeds under the very same RP configuration; only its signature is changed.
    @Test
    void jwtValidationRejectsTamperedSignatures() throws Exception {
        require(IdpAdapter.Capability.JWT_ACCESS_TOKEN);
        String token = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("access_token").orElseThrow();
        int signature = token.lastIndexOf('.') + 1;
        String tampered = token.substring(0, signature) + (token.charAt(signature) == 'A' ? 'B' : 'A')
                + token.substring(signature + 1);
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false, _ -> { })) {
            assertApi(rp, token, Status.OK_200);
            assertApi(rp, tampered, Status.UNAUTHORIZED_401);
        }
    }

    // RFC 9700 §2.3: if a token was not intended for this resource server,
    // "the resource server MUST refuse to serve the respective request."
    // Rejecting an ID Token as a Bearer access token is enforced by the configured JWT profile,
    // even when the ID Token's (client) audience is accepted as an API audience for this test.
    @Test
    void jwtValidationRejectsAnIdTokenEvenWhenItsAudienceMatches() throws Exception {
        require(IdpAdapter.Capability.JWT_ACCESS_TOKEN);
        String idToken = userTokens(IdpAdapter.ClientMode.JWT_ACCESS).stringValue("id_token").orElseThrow();
        assertThat(SignedJwt.parseToken(idToken).getJwt().audience().orElseThrow(),
                   hasItems(IdpAdapter.ClientMode.JWT_ACCESS.id()));
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.JWT_ACCESS, false,
                tenant -> changeAudience(tenant, IdpAdapter.ClientMode.JWT_ACCESS.id()))) {
            assertApi(rp, idToken, Status.UNAUTHORIZED_401);
        }
    }

    // RFC 9126 §2.2 (https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2):
    // "the server MUST generate a request URI and provide it in the response" to a valid PAR.
    // This live-OP test also completes the authorization-code browser login.
    @Test
    void pushedAuthorizationRequestCompletesTheBrowserLogin() throws Exception {
        require(IdpAdapter.Capability.PAR);
        assertBrowserAuthentication(IdpAdapter.ClientMode.PAR);
    }

    // RFC 9101 §6.2 (https://www.rfc-editor.org/rfc/rfc9101.html#section-6.2):
    // "The authorization server MUST validate the signature" of a signed Request Object.
    // The native OP's successful browser login is the external acceptance check.
    @Test
    void signedRequestObjectCompletesTheBrowserLogin() throws Exception {
        require(IdpAdapter.Capability.JAR);
        assertBrowserAuthentication(IdpAdapter.ClientMode.JAR);
    }

    // RFC 9126 §3 (https://www.rfc-editor.org/rfc/rfc9126.html#section-3):
    // "Clients MAY use the `request` parameter as defined in JAR" to push a signed JWT.
    // The real OP processes the combined PAR/JAR request and completes authentication.
    @Test
    void pushedAuthorizationAndSignedRequestObjectCompleteTheBrowserLoginTogether() throws Exception {
        require(IdpAdapter.Capability.PAR);
        require(IdpAdapter.Capability.JAR);
        require(IdpAdapter.Capability.PAR_WITH_JAR);
        assertBrowserAuthentication(IdpAdapter.ClientMode.PAR_JAR);
    }

    /*
     * Spec: OpenID Connect Core 1.0, 5.3.2, Successful UserInfo Response.
     * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
     * Quote: "the content-type MUST be `application/jwt`."
     */
    @Test
    void signedUserInfoCompletesTheBrowserLogin() throws Exception {
        require(IdpAdapter.Capability.SIGNED_USERINFO);
        URI endpoint = URI.create(metadata().stringValue("userinfo_endpoint").orElseThrow());
        try (UserInfoRecorder recorder = new UserInfoRecorder(adapter, endpoint);
             RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.SIGNED_USERINFO, true,
                     tenant -> tenant.endpoints(endpoints -> endpoints.userInfoEndpointUri(recorder.uri())));
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.OK_200));
                JsonObject subject = response.as(JsonObject.class);
                assertMappedUserSubject(subject);
                assertUserInfoSubjectMatches(subject, recordedUserInfoSubject(recorder, true));
            }
        }
    }

    // OIDC Core 1.0 §3.1.3.7(1) (https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation):
    // "If the ID Token is encrypted, decrypt it using the keys and algorithms" negotiated by the RP.
    // This live-provider test checks the resulting authenticated identity and role mapping.
    @Test
    void encryptedIdTokenCompletesTheBrowserLogin() throws Exception {
        require(IdpAdapter.Capability.ENCRYPTED_ID_TOKEN);
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.ENCRYPTED_ID_TOKEN, true, _ -> { });
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.OK_200));
                assertMappedUserSubject(response.as(JsonObject.class));
            }
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/roles/reader"))) {
                assertThat(response.status(), is(Status.OK_200));
            }
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/roles/admin"))) {
                assertThat(response.status(), is(Status.FORBIDDEN_403));
            }
        }
    }

    // RP-Initiated Logout 1.0 §2 (https://openid.net/specs/openid-connect-rpinitiated-1_0.html):
    // "An RP requests that the OP log out the End-User by redirecting" the browser.
    // An OP may display a confirmation page here, so an HTTP 200 alone does not prove its session ended.
    @Test
    void rpInitiatedLogoutReachesProviderEndpointAndClearsLocalSession() throws Exception {
        require(IdpAdapter.Capability.RP_LOGOUT);
        try (RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.BASIC, true,
                tenant -> tenant.logout(OidcLogoutConfig.builder().endSession(end -> end.enabled(true)).buildPrototype()));
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            String cookieName = OidcCookieConfig.create().localAuthenticationCookieName();
            assertThat(browser.cookieValue(cookieName).isPresent(), is(true));
            try (HttpClientResponse response = browser.post(rp.baseUri().resolve("/oidc/logout"), Parameters.empty("logout"))) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
                URI endSession = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                assertThat(UriQuery.create(endSession).contains("id_token_hint"), is(true));
                try (HttpClientResponse providerResponse = browser.get(endSession)) {
                    assertThat(providerResponse.status(), is(Status.OK_200));
                }
            }
            assertThat(browser.cookieValue(cookieName), is(Optional.empty()));
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(response.status(), is(Status.SEE_OTHER_303));
            }
        }
    }

    // RFC 6750 §2.1 (https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1):
    // "the client uses the \"Bearer\" authentication scheme to transmit the access token."
    // Forwarding the *same* validated token is a configured Helidon strategy, not a protocol requirement.
    @Test
    void outboundTokenPropagationPreservesTheValidatedAccessToken() throws Exception {
        assertOutbound(OidcOutboundPolicyConfig.builder().strategy(OidcOutboundStrategy.TOKEN_PROPAGATION)
                .audience(IdpAdapter.AUDIENCE).buildPrototype(), true, false);
    }

    // RFC 6749 §4.4.3 (https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.3):
    // "the authorization server issues an access token" for a valid client-credentials request.
    // Helidon also caches the independently acquired token as a local optimization.
    @Test
    void outboundClientCredentialsAcquiresAndCachesItsOwnAccessToken() throws Exception {
        assertOutbound(OidcOutboundPolicyConfig.builder().strategy(OidcOutboundStrategy.CLIENT_CREDENTIALS)
                .clientCredentialsScopes(List.of("resource.read")).buildPrototype(), false, true);
    }

    // RFC 8693 §2.1 (https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1):
    // `audience` is "OPTIONAL. The logical name of the target service" for token exchange.
    // The RP requests an explicit audience and then checks its bearer token at the API.
    @Test
    void outboundTokenExchangeObtainsATokenForTheTargetAudience() throws Exception {
        require(IdpAdapter.Capability.TOKEN_EXCHANGE);
        assertOutbound(OidcOutboundPolicyConfig.builder().strategy(OidcOutboundStrategy.TOKEN_EXCHANGE)
                .tokenExchangeAudience(IdpAdapter.AUDIENCE).tokenExchangeScopes(List.of("resource.read"))
                .buildPrototype(), false, false);
    }

    // OIDC Core 1.0 §5.3.2 (https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse):
    // "If signed, the UserInfo Response MUST contain the Claims `iss` (issuer) and `aud` (audience)".
    // This helper is invoked only for an OP that actually omits both claims from signed UserInfo.
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

    // RFC 9126 §3 (https://www.rfc-editor.org/rfc/rfc9126.html#section-3):
    // "All other request parameters" "MUST appear as claims of the JWT" when pushing `request`.
    // The RP sends only the signed Request Object, so the OP's 400 is a tested provider limitation,
    // not a claim that the RP's compliant JAR/PAR request must fail.
    void assertCompliantParWithJarIsRejectedByTheProvider() throws Exception {
        URI nativePar = URI.create(metadata().stringValue("pushed_authorization_request_endpoint").orElseThrow());
        try (OidcEndpointRecorder recorder = new OidcEndpointRecorder(adapter, nativePar);
             RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.PAR_JAR, true,
                     tenant -> tenant.endpoints(endpoints -> endpoints.pushedAuthorizationRequestEndpointUri(recorder.uri())));
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(recorder.diagnostics(), response.status(), is(Status.SERVICE_UNAVAILABLE_503));
            }
            assertThat(recorder.exchanges(), hasSize(1));
            OidcEndpointRecorder.Exchange rejected = recorder.exchanges().getFirst();
            assertThat(rejected.parameterNames(), is(Set.of("request")));
            assertThat(rejected.status(), is(Status.BAD_REQUEST_400));
            assertThat(rejected.response().stringValue("error").orElseThrow(), is("invalid_request_object"));
            assertThat(rejected.response().toString(), containsString("response_type"));
            assertThat(browser.cookieValue(OidcCookieConfig.create().localAuthenticationCookieName()), is(Optional.empty()));
        }
    }

    // RFC 6749 §5.2 (https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2) defines token errors.
    // A revoked refresh token yielding an OP 500 here is provider-specific; retaining the already
    // authenticated (but not renewed) local session is Helidon fallback policy, not a spec MUST.
    void assertRefreshRevocationServerErrorDoesNotRenewTheSession() throws Exception {
        URI tokenEndpoint = URI.create(metadata().stringValue("token_endpoint").orElseThrow());
        try (OidcEndpointRecorder recorder = new OidcEndpointRecorder(adapter, tokenEndpoint);
             RelyingParty rp = new RelyingParty(adapter, IdpAdapter.ClientMode.SHORT_LIVED, true,
                     tenant -> configureRefresh(tenant, recorder.uri()));
             TestBrowser browser = new TestBrowser(adapter.webClient())) {
            authenticate(browser, rp);
            JsonObject initial = recorder.exchanges().getFirst().response();
            String cookieName = OidcCookieConfig.create().localAuthenticationCookieName();
            String originalCookie = browser.cookieValue(cookieName).orElseThrow();
            revokeToken(IdpAdapter.ClientMode.SHORT_LIVED, initial.stringValue("refresh_token").orElseThrow(),
                        "refresh_token");
            try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                assertThat(recorder.diagnostics(), response.status(), is(Status.OK_200));
                assertThat(response.as(JsonObject.class).stringValue("access_token"), is(initial.stringValue("access_token")));
                assertThat(response.headers().first(HeaderNames.SET_COOKIE), is(Optional.empty()));
            }
            assertThat(recorder.exchanges().stream().map(OidcEndpointRecorder.Exchange::grantType).toList(),
                       contains("authorization_code", "refresh_token"));
            OidcEndpointRecorder.Exchange rejected = recorder.exchanges().getLast();
            assertThat(rejected.status(), is(Status.INTERNAL_SERVER_ERROR_500));
            assertThat(rejected.response().stringValue("error").orElseThrow(), is("server_error"));
            assertThat(rejected.response().stringValue("error_description").orElseThrow(), containsString("no rows affected"));
            assertThat(rejected.response().value("access_token"), is(Optional.empty()));
            assertThat(browser.cookieValue(cookieName), is(Optional.of(originalCookie)));
        }
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

    private void assertMappedUserSubject(JsonObject subject) {
        // A browser subject is keyed by the ID Token's issuer and sub, not just by the display name.
        String issuerPrefix = "oidc-sub:" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(adapter.issuer().toString().getBytes(StandardCharsets.UTF_8)) + ".";
        String id = subject.stringValue("id").orElseThrow();
        assertThat(id, startsWith(issuerPrefix));
        assertThat(id.length() > issuerPrefix.length(), is(true));
        assertThat(subject.stringValue("name").orElseThrow(), is("alice"));
        assertThat(subject.stringValue("email").orElseThrow(), is("alice@example.org"));
        assertThat(subject.arrayValue("roles").orElseThrow().values().stream()
                           .map(value -> value.asString().value()).toList(), hasItems("reader"));
        assertThat(subject.arrayValue("scopes").orElseThrow().values().stream()
                           .map(value -> value.asString().value()).toList(), hasItems("resource.read"));
        assertThat(subject.stringValue("access_token").orElseThrow().isBlank(), is(false));
    }

    private String recordedUserInfoSubject(UserInfoRecorder recorder, boolean signed) {
        UserInfoRecorder.Exchange exchange = recorder.exchange();
        assertThat(exchange.status(), is(Status.OK_200));
        assertThat(exchange.authorization(), startsWith("Bearer "));
        assertThat(exchange.contentType(), startsWith(signed ? "application/jwt" : "application/json"));
        if (signed) {
            var jwt = SignedJwt.parseToken(exchange.body()).getJwt();
            assertThat(jwt.algorithm().orElseThrow(), is("RS256"));
            assertThat(jwt.issuer().orElseThrow(), is(adapter.issuer().toString()));
            assertThat(jwt.audience().orElseThrow(), hasItems(IdpAdapter.ClientMode.SIGNED_USERINFO.id()));
            return jwt.subject().orElseThrow();
        }
        return JsonParser.create(exchange.body()).readJsonObject().stringValue("sub").orElseThrow();
    }

    private static void assertUserInfoSubjectMatches(JsonObject subject, String userInfoSubject) {
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(userInfoSubject.getBytes(StandardCharsets.UTF_8));
        assertThat(subject.stringValue("id").orElseThrow(), endsWith("." + encoded));
    }

    JsonObject userTokens(IdpAdapter.ClientMode mode) throws Exception {
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

    final JsonObject metadata() {
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
        return assertResource(rp, "/api", token, expected);
    }

    private JsonObject assertResource(RelyingParty rp, String path, String token, Status expected) {
        WebClient client = WebClient.builder().from(adapter.webClient()).build();
        try {
            var request = client.get().uri(rp.baseUri().resolve(path));
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

    private static void configureRefresh(OidcTenantConfig.Builder tenant, URI tokenEndpoint) {
        tenant.authorizationCode(OidcAuthorizationCodeConfig.builder().from(tenant.authorizationCode().orElseThrow())
                .scopes(List.of("openid", "profile", "email", "groups", "resource.read", "offline_access"))
                .buildPrototype());
        tenant.endpoints(endpoints -> endpoints.tokenEndpointUri(tokenEndpoint));
    }

    private static URI withQueryParameter(URI uri, String name, String value) {
        UriQuery original = UriQuery.create(uri);
        Map<String, String> parameters = new LinkedHashMap<>();
        for (String parameter : original.names()) {
            parameters.put(parameter, original.first(parameter).orElseThrow());
        }
        parameters.put(name, value);
        return URI.create(uri.getScheme() + "://" + uri.getAuthority() + uri.getPath() + "?" + query(parameters));
    }

    private void revokeToken(IdpAdapter.ClientMode mode, String token, String hint) {
        URI endpoint = URI.create(metadata().stringValue("revocation_endpoint").orElseThrow());
        WebClient client = WebClient.builder().from(adapter.webClient()).build();
        String basic = Base64.getEncoder().encodeToString((mode.id() + ":" + IdpAdapter.SECRET).getBytes(StandardCharsets.UTF_8));
        try (HttpClientResponse response = client.post().uri(endpoint).header(HeaderNames.AUTHORIZATION, "Basic " + basic)
                .submit(Parameters.builder("revocation").add("token", token).add("token_type_hint", hint).build())) {
            assertThat(response.status(), is(Status.OK_200));
        } finally {
            client.closeResource();
        }
    }

    private void assertRejectedCallback(TestBrowser browser, RelyingParty rp, URI callback, Status expected) throws Exception {
        try (HttpClientResponse response = browser.get(callback)) {
            assertThat(response.status(), is(expected));
        }
        try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
            assertThat(response.status(), is(Status.SEE_OTHER_303));
        }
        assertThat(browser.cookieValue(OidcCookieConfig.create().localAuthenticationCookieName()), is(Optional.empty()));
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
            String diagnostics = response.status().equals(Status.SEE_OTHER_303) ? "" : "\n" + adapter.diagnostics();
            assertThat("Authorization response: " + detail + diagnostics, response.status(), is(Status.SEE_OTHER_303));
            URI uri = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
            UriQuery query = UriQuery.create(uri);
            if (!query.contains("request") && !query.contains("request_uri")) {
                assertThat(query.first("code_challenge_method").orElseThrow(), is("S256"));
                assertThat(query.first("code_challenge").orElseThrow().length(), is(43));
            }
            return uri;
        }
    }

    final URI authenticate(TestBrowser browser, RelyingParty rp) throws Exception {
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

    private static final class UserInfoRecorder implements AutoCloseable {
        private final List<Exchange> exchanges = new CopyOnWriteArrayList<>();
        private final WebClient client;
        private final WebServer server;

        private UserInfoRecorder(IdpAdapter adapter, URI nativeEndpoint) {
            client = WebClient.builder().from(adapter.webClient()).servicesDiscoverServices(false).build();
            try {
                server = WebServer.builder().host("127.0.0.1").port(0).tls(IdpResources.serverTls())
                        .routing(routing -> routing.get("/userinfo", (request, response) -> {
                            String authorization = request.headers().first(HeaderNames.AUTHORIZATION).orElseThrow();
                            String accept = request.headers().first(HeaderNames.ACCEPT).orElseThrow();
                            try (HttpClientResponse nativeResponse = client.get().uri(nativeEndpoint)
                                    .followRedirects(false)
                                    .header(HeaderNames.AUTHORIZATION, authorization)
                                    .header(HeaderNames.ACCEPT, accept).request()) {
                                String body = nativeResponse.as(String.class);
                                String contentType = nativeResponse.headers().first(HeaderNames.CONTENT_TYPE).orElse("");
                                exchanges.add(new Exchange(authorization, nativeResponse.status(), contentType, body));
                                if (!contentType.isEmpty()) {
                                    response.headers().set(HeaderNames.CONTENT_TYPE, contentType);
                                }
                                response.status(nativeResponse.status()).send(body);
                            }
                        })).build().start();
            } catch (RuntimeException e) {
                client.closeResource();
                throw e;
            }
        }

        private URI uri() {
            return URI.create("https://localhost:" + server.port() + "/userinfo");
        }

        private Exchange exchange() {
            assertThat("Expected exactly one UserInfo HTTP exchange", exchanges, hasSize(1));
            return exchanges.getFirst();
        }

        @Override
        public void close() {
            try {
                server.stop();
            } finally {
                client.closeResource();
            }
        }

        private record Exchange(String authorization, Status status, String contentType, String body) {
        }
    }
}
