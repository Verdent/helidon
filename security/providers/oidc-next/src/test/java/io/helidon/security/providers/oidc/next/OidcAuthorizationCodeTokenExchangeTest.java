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
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.pki.Keys;
import io.helidon.common.tls.Tls;
import io.helidon.common.tls.TlsClientAuth;
import io.helidon.http.HeaderNames;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkOctet;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.WebServerConfig;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;
import io.helidon.webserver.testing.junit5.SetUpServer;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ServerTest
class OidcAuthorizationCodeTokenExchangeTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback?registered=true");
    private static final String CLIENT_ID = "client/id";
    private static final String CLIENT_SECRET = "client+secret=value";
    private static final String AUTHORIZATION_CODE = "authorization-code+value";
    private static final String PKCE_VERIFIER = "pkce-verifier+value";
    private static final String REFRESH_TOKEN = "refresh-token+value";
    private static final String CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static volatile int responseStatus;
    private static volatile String responseBody;
    private static volatile String responseContentType;
    private static volatile String responseCacheControl;
    private static volatile String responsePragma;
    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();

    private static JwkKeys signKeys;

    private final URI mutualTlsServerUri;

    private URI tokenEndpointUri;
    private URI mutualTlsTokenEndpointUri;

    OidcAuthorizationCodeTokenExchangeTest(WebServer server) {
        mutualTlsServerUri = URI.create("https://localhost:" + server.port("mtls") + "/");
    }

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.post("/token", OidcAuthorizationCodeTokenExchangeTest::handleTokenEndpoint);
    }

    @SetUpRoute("mtls")
    static void mutualTlsRouting(HttpRouting.Builder routing) {
        routing.post("/token", OidcAuthorizationCodeTokenExchangeTest::handleTokenEndpoint);
    }

    @SetUpServer
    static void server(WebServerConfig.Builder builder) {
        builder.putSocket("mtls", socket -> socket.tls(serverTls()));
    }

    @BeforeEach
    void setUp(URI serverUri) {
        tokenEndpointUri = serverUri.resolve("token");
        mutualTlsTokenEndpointUri = mutualTlsServerUri.resolve("token");
        responseStatus = 200;
        responseBody = validTokenResponse().toString();
        responseContentType = "application/json";
        responseCacheControl = "no-store";
        responsePragma = "no-cache";
        RECORDED_REQUEST.set(null);
    }

    @Test
    void authorizationCodeExchangePostsCodeVerifierAndUsesClientSecretBasic() {
        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(true));
        OidcTokenResponse tokenResponse = result.tokenResponse().orElseThrow();
        assertThat(tokenResponse.accessToken(), is("access-token"));
        assertThat(tokenResponse.tokenType(), is("Bearer"));
        assertThat(tokenResponse.idToken().orElse(""), is("id-token"));
        assertThat(tokenResponse.refreshToken().orElse(""), is("refresh-token"));
        assertThat(tokenResponse.expiresIn().orElseThrow(), is(3600L));
        assertThat(tokenResponse.scope().orElse(""), is("openid profile"));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request, is(notNullValue()));
        assertThat(request.method(), is("POST"));
        assertThat(request.authorization(),
                   is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
        assertThat(request.contentType(), is("application/x-www-form-urlencoded"));
        assertThat(request.cacheControl(), hasItem("no-store"));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("authorization_code"),
                                                       "code", List.of(AUTHORIZATION_CODE),
                                                       "redirect_uri", List.of(REDIRECTION_ENDPOINT_URI.toString()),
                                                       "code_verifier", List.of(PKCE_VERIFIER))));
    }

    @Test
    void refreshTokenGrantPostsRefreshTokenAndUsesClientAuthentication() {
        responseBody = JsonObject.builder()
                .set("access_token", "refreshed-access-token")
                .set("token_type", "Bearer")
                .set("refresh_token", "rotated-refresh-token")
                .set("expires_in", 600)
                .set("scope", "openid email")
                .build()
                .toString();

        OidcTokenEndpointResult result = refresh(confidentialTenant(), REFRESH_TOKEN);

        assertThat(result.succeeded(), is(true));
        OidcTokenResponse tokenResponse = result.tokenResponse().orElseThrow();
        assertThat(tokenResponse.accessToken(), is("refreshed-access-token"));
        assertThat(tokenResponse.idToken().isEmpty(), is(true));
        assertThat(tokenResponse.refreshToken().orElse(""), is("rotated-refresh-token"));
        assertThat(tokenResponse.expiresIn().orElseThrow(), is(600L));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request, is(notNullValue()));
        assertThat(request.authorization(),
                   is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("refresh_token"),
                                                       "refresh_token", List.of(REFRESH_TOKEN))));
    }

    @Test
    void refreshTokenGrantForPublicClientSendsClientIdInForm() {
        responseBody = validRefreshResponse().toString();

        OidcTokenEndpointResult result = refresh(publicTenant(), REFRESH_TOKEN);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("refresh_token"),
                                                       "refresh_token", List.of(REFRESH_TOKEN),
                                                       "client_id", List.of(CLIENT_ID))));
    }

    @Test
    void refreshTokenGrantWithClientSecretPostSendsCredentialsInForm() {
        responseBody = validRefreshResponse().toString();

        OidcTokenEndpointResult result = refresh(confidentialTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_POST),
                                                 REFRESH_TOKEN);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("refresh_token"),
                                                       "refresh_token", List.of(REFRESH_TOKEN),
                                                       "client_id", List.of(CLIENT_ID),
                                                       "client_secret", List.of(CLIENT_SECRET))));
    }

    @Test
    void refreshTokenGrantWithMutualTlsSendsClientIdInForm() {
        responseBody = validRefreshResponse().toString();

        OidcTokenEndpointResult result = refresh(mutualTlsTenant(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH),
                                                 REFRESH_TOKEN);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("refresh_token"),
                                                       "refresh_token", List.of(REFRESH_TOKEN),
                                                       "client_id", List.of(CLIENT_ID))));
    }

    @Test
    void publicClientSendsClientIdInForm() {
        OidcTokenEndpointResult result = exchange(publicTenant(), null);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("authorization_code"),
                                                       "code", List.of(AUTHORIZATION_CODE),
                                                       "redirect_uri", List.of(REDIRECTION_ENDPOINT_URI.toString()),
                                                       "client_id", List.of(CLIENT_ID))));
    }

    @Test
    void clientSecretPostSendsCredentialsInForm() {
        OidcTokenEndpointResult result = exchange(confidentialTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_POST),
                                                  PKCE_VERIFIER);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("authorization_code"),
                                                       "code", List.of(AUTHORIZATION_CODE),
                                                       "redirect_uri", List.of(REDIRECTION_ENDPOINT_URI.toString()),
                                                       "code_verifier", List.of(PKCE_VERIFIER),
                                                       "client_id", List.of(CLIENT_ID),
                                                       "client_secret", List.of(CLIENT_SECRET))));
    }

    @Test
    void tlsClientAuthSendsClientIdInForm() {
        OidcTokenEndpointResult result = exchange(mutualTlsTenant(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH),
                                                  PKCE_VERIFIER);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("authorization_code"),
                                                       "code", List.of(AUTHORIZATION_CODE),
                                                       "redirect_uri", List.of(REDIRECTION_ENDPOINT_URI.toString()),
                                                       "code_verifier", List.of(PKCE_VERIFIER),
                                                       "client_id", List.of(CLIENT_ID))));
    }

    @Test
    void selfSignedTlsClientAuthSendsClientIdInForm() {
        OidcTokenEndpointResult result = exchange(
                mutualTlsTenant(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH),
                PKCE_VERIFIER);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("authorization_code"),
                                                       "code", List.of(AUTHORIZATION_CODE),
                                                       "redirect_uri", List.of(REDIRECTION_ENDPOINT_URI.toString()),
                                                       "code_verifier", List.of(PKCE_VERIFIER),
                                                       "client_id", List.of(CLIENT_ID))));
    }

    @Test
    void clientSecretJwtSendsClientAssertion() {
        OidcTokenEndpointResult result = exchange(confidentialTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT),
                                                  PKCE_VERIFIER);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters().get("client_assertion_type"), is(List.of(CLIENT_ASSERTION_TYPE)));
        assertThat(request.formParameters().containsKey("client_secret"), is(false));
        assertThat(request.formParameters().containsKey("client_id"), is(false));

        String assertion = request.formParameters().get("client_assertion").get(0);
        SignedJwt signedJwt = SignedJwt.parseToken(assertion);
        signedJwt.verifySignature(null, clientSecretJwk()).checkValid();
        assertClientAssertionClaims(signedJwt);
        assertThat(signedJwt.getJwt().algorithm().orElse(""), is("HS256"));
    }

    @Test
    void privateKeyJwtSendsClientAssertion() {
        OidcTokenEndpointResult result = exchange(privateKeyJwtTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters().get("client_assertion_type"), is(List.of(CLIENT_ASSERTION_TYPE)));
        assertThat(request.formParameters().containsKey("client_secret"), is(false));
        assertThat(request.formParameters().containsKey("client_id"), is(false));

        String assertion = request.formParameters().get("client_assertion").get(0);
        SignedJwt signedJwt = SignedJwt.parseToken(assertion);
        signedJwt.verifySignature(signKeys).checkValid();
        assertClientAssertionClaims(signedJwt);
        assertThat(signedJwt.getJwt().algorithm().orElse(""), is("RS256"));
        assertThat(signedJwt.getJwt().keyId().orElse(""), is("sign-rsa"));
    }

    @Test
    void privateKeyJwtReusesConfiguredJwkResource() {
        OidcEndpointClient endpointClient = OidcTenantContext.ready("default", privateKeyJwtTenant())
                .endpointClient();

        OidcTokenEndpointResult first = endpointClient.exchangeAuthorizationCode(AUTHORIZATION_CODE,
                                                                                 REDIRECTION_ENDPOINT_URI,
                                                                                 Optional.of(PKCE_VERIFIER));
        OidcTokenEndpointResult second = endpointClient.exchangeAuthorizationCode(AUTHORIZATION_CODE,
                                                                                  REDIRECTION_ENDPOINT_URI,
                                                                                  Optional.of(PKCE_VERIFIER));

        assertThat(first.succeeded(), is(true));
        assertThat(second.succeeded(), is(true));
    }

    @Test
    void privateKeyJwtRejectsMismatchedConfiguredAlgorithm() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantContext.ready("default",
                                                                                    privateKeyJwtTenant("RS384")));

        assertThat(thrown.getMessage(), containsString("client-assertion.algorithm"));
    }

    @Test
    void privateKeyJwtRequiresKeyIdForMultiKeyJwk() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantContext.ready("default",
                                                                                    privateKeyJwtTenant("RS256",
                                                                                                        null)));

        assertThat(thrown.getMessage(), containsString("client-assertion.key-id"));
    }

    @Test
    void privateKeyJwtRejectsUnknownKeyId() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantContext.ready("default",
                                                                                    privateKeyJwtTenant("RS256",
                                                                                                        "missing")));

        assertThat(thrown.getMessage(), containsString("client-assertion.key-id"));
    }

    @Test
    void tokenEndpointErrorResponseIsParsed() {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid_grant")
                .set("error_description", "authorization code expired")
                .set("error_uri", "https://issuer.example/errors/invalid-grant")
                .build()
                .toString();

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.errorResponse(), is(true));
        OidcTokenErrorResponse error = result.error().orElseThrow();
        assertThat(error.error(), is("invalid_grant"));
        assertThat(error.errorDescription().orElse(""), is("authorization code expired"));
        assertThat(error.errorUri().orElse(""), is("https://issuer.example/errors/invalid-grant"));
    }

    @Test
    void invalidSuccessfulTokenResponseFails() {
        responseBody = JsonObject.builder()
                .set("access_token", "access-token")
                .set("token_type", "Bearer")
                .build()
                .toString();

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint response is invalid"));
    }

    @Test
    void malformedScopeInSuccessfulTokenResponseFails() {
        responseBody = validTokenResponse(it -> it.set("scope", "openid\tprofile")).toString();

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint response is invalid"));
    }

    @Test
    void successfulTokenResponseRequiresJsonContentType() {
        responseContentType = "text/plain";

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint response is invalid"));
    }

    @Test
    void successfulTokenResponseRequiresNoStoreCacheControl() {
        responseCacheControl = "private";

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint response is invalid"));
    }

    @Test
    void successfulTokenResponseRequiresNoCachePragma() {
        responsePragma = "cache";

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint response is invalid"));
    }

    @Test
    void malformedTokenEndpointErrorResponseFails() {
        responseStatus = 400;
        responseBody = "{not-json";

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint Error Response is invalid"));
    }

    @Test
    void tokenEndpointErrorResponseRequiresJsonContentType() {
        responseStatus = 400;
        responseContentType = "text/plain";
        responseBody = JsonObject.builder()
                .set("error", "invalid_grant")
                .build()
                .toString();

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint Error Response is invalid"));
    }

    @Test
    void tokenEndpointErrorResponseRejectsInvalidErrorCharacters() {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid\\grant")
                .build()
                .toString();

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint Error Response is invalid"));

        responseBody = JsonObject.builder()
                .set("error", "invalid_grant")
                .set("error_description", "invalid \"grant\"")
                .build()
                .toString();

        result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint Error Response is invalid"));

        responseBody = JsonObject.builder()
                .set("error", "invalid_grant")
                .set("error_uri", "https://issuer.example/error docs")
                .build()
                .toString();

        result = exchange(confidentialTenant(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(false));
        assertThat(result.description(), is("Token Endpoint Error Response is invalid"));
    }

    private static void handleTokenEndpoint(ServerRequest request, ServerResponse response) {
        RECORDED_REQUEST.set(new RecordedRequest(request.prologue().method().text(),
                                                request.headers().first(HeaderNames.AUTHORIZATION).orElse(""),
                                                request.headers().first(HeaderNames.CONTENT_TYPE).orElse(""),
                                                request.headers().get(HeaderNames.CACHE_CONTROL).allValues(),
                                                formParameters(request.content().as(Parameters.class))));
        response.status(responseStatus);
        if (responseContentType != null) {
            response.header(HeaderNames.CONTENT_TYPE, responseContentType);
        }
        if (responseCacheControl != null) {
            response.header(HeaderNames.CACHE_CONTROL, responseCacheControl);
        }
        if (responsePragma != null) {
            response.header(HeaderNames.PRAGMA, responsePragma);
        }
        response.send(responseBody);
    }

    private OidcTokenEndpointResult exchange(OidcTenantConfig tenantConfig, String pkceVerifier) {
        return OidcTenantContext.ready("default", tenantConfig)
                .endpointClient()
                .exchangeAuthorizationCode(AUTHORIZATION_CODE,
                                           REDIRECTION_ENDPOINT_URI,
                                           Optional.ofNullable(pkceVerifier));
    }

    private OidcTokenEndpointResult refresh(OidcTenantConfig tenantConfig, String refreshToken) {
        return OidcTenantContext.ready("default", tenantConfig)
                .endpointClient()
                .refreshAccessToken(refreshToken);
    }

    private OidcTenantConfig confidentialTenant() {
        return tenant(true, null);
    }

    private OidcTenantConfig confidentialTenant(OidcClientAuthenticationMethod method) {
        return tenant(true, method);
    }

    private OidcTenantConfig publicTenant() {
        return tenant(false, OidcClientAuthenticationMethod.NONE);
    }

    private OidcTenantConfig mutualTlsTenant(OidcClientAuthenticationMethod method) {
        return tenant(false, method);
    }

    private OidcTenantConfig privateKeyJwtTenant() {
        return privateKeyJwtTenant("RS256", "sign-rsa");
    }

    private OidcTenantConfig privateKeyJwtTenant(String algorithm) {
        return privateKeyJwtTenant(algorithm, "sign-rsa");
    }

    private OidcTenantConfig privateKeyJwtTenant(String algorithm, String keyId) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertion(it -> {
                    it.jwk(Resource.create("oidc-next-sign-jwk.json"))
                            .algorithm(algorithm);
                    if (keyId != null) {
                        it.keyId(keyId);
                    }
                })
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();
    }

    private OidcTenantConfig tenant(boolean clientSecret, OidcClientAuthenticationMethod method) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .update(builder -> {
                    if (clientSecret) {
                        builder.clientSecret(CLIENT_SECRET);
                    }
                })
                .update(builder -> {
                    if (method != null) {
                        builder.tokenEndpointAuthenticationMethod(method);
                        if (method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH) {
                            builder.webClient(mutualTlsWebClient());
                        }
                    }
                })
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                                                  || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH
                                                  ? mutualTlsTokenEndpointUri
                                                  : tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();
    }

    private static WebClientConfig mutualTlsWebClient() {
        Keys privateKeyConfig = clientKeys();
        return WebClientConfig.builder()
                .tls(tls -> tls
                        .privateKey(privateKeyConfig)
                        .privateKeyCertChain(privateKeyConfig)
                        .trust(trust -> trust
                                .keystore(store -> store
                                        .passphrase("password")
                                        .trustStore(true)
                                        .keystore(Resource.create("client.p12")))))
                .buildPrototype();
    }

    private static Tls serverTls() {
        Keys privateKeyConfig = serverKeys();
        return Tls.builder()
                .clientAuth(TlsClientAuth.REQUIRED)
                .privateKey(privateKeyConfig)
                .privateKeyCertChain(privateKeyConfig)
                .trust(trust -> trust
                        .keystore(store -> store
                                .passphrase("password")
                                .trustStore(true)
                                .keystore(Resource.create("server.p12"))))
                .build();
    }

    private static Keys clientKeys() {
        return Keys.builder()
                .keystore(store -> store
                        .passphrase("password")
                        .keystore(Resource.create("client.p12")))
                .build();
    }

    private static Keys serverKeys() {
        return Keys.builder()
                .keystore(store -> store
                        .passphrase("password")
                        .keystore(Resource.create("server.p12")))
                .build();
    }

    private static JsonObject validTokenResponse() {
        return validTokenResponse(it -> { });
    }

    private static JsonObject validTokenResponse(Consumer<JsonObject.Builder> customizer) {
        JsonObject.Builder builder = JsonObject.builder()
                .set("access_token", "access-token")
                .set("token_type", "Bearer")
                .set("id_token", "id-token")
                .set("refresh_token", "refresh-token")
                .set("expires_in", 3600)
                .set("scope", "openid profile");
        customizer.accept(builder);
        return builder.build();
    }

    private static JsonObject validRefreshResponse() {
        return JsonObject.builder()
                .set("access_token", "refreshed-access-token")
                .set("token_type", "Bearer")
                .set("expires_in", 600)
                .build();
    }

    private static Map<String, List<String>> formParameters(Parameters parameters) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (String name : parameters.names()) {
            result.put(name, parameters.all(name));
        }
        return result;
    }

    private void assertClientAssertionClaims(SignedJwt signedJwt) {
        assertThat(signedJwt.getJwt().issuer().orElse(""), is(CLIENT_ID));
        assertThat(signedJwt.getJwt().subject().orElse(""), is(CLIENT_ID));
        assertThat(signedJwt.getJwt().audience().orElseThrow(), is(List.of(tokenEndpointUri.toString())));
        assertThat(signedJwt.getJwt().jwtId().isPresent(), is(true));
        assertThat(signedJwt.getJwt().issueTime().isPresent(), is(true));
        assertThat(signedJwt.getJwt().expirationTime().isPresent(), is(true));
        assertThat(signedJwt.getJwt().payloadClaimsJson().keySet(), is(Set.of("iss", "sub", "aud", "jti", "iat", "exp")));
    }

    private static Jwk clientSecretJwk() {
        return JwkOctet.create(JsonObject.builder()
                                      .set("kty", "oct")
                                      .set("alg", "HS256")
                                      .set("kid", "client-secret")
                                      .set("k", base64Url(CLIENT_SECRET.getBytes(StandardCharsets.UTF_8)))
                                      .build());
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    private record RecordedRequest(String method,
                                   String authorization,
                                   String contentType,
                                   List<String> cacheControl,
                                   Map<String, List<String>> formParameters) {
    }
}
