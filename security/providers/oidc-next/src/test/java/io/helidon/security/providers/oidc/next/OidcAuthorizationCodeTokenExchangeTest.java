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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;

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

    private static volatile int responseStatus;
    private static volatile String responseBody;
    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();

    private URI tokenEndpointUri;

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.post("/token", OidcAuthorizationCodeTokenExchangeTest::handleTokenEndpoint);
    }

    @BeforeEach
    void setUp(URI serverUri) {
        tokenEndpointUri = serverUri.resolve("token");
        responseStatus = 200;
        responseBody = validTokenResponse().toString();
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
    void malformedTokenEndpointErrorResponseFails() {
        responseStatus = 400;
        responseBody = "{not-json";

        OidcTokenEndpointResult result = exchange(confidentialTenant(), PKCE_VERIFIER);

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
        response.status(responseStatus)
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .send(responseBody);
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

    private OidcTenantConfig tenant(boolean clientSecret, OidcClientAuthenticationMethod method) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .update(builder -> {
                    if (clientSecret) {
                        builder.clientSecret(CLIENT_SECRET);
                    }
                })
                .update(builder -> {
                    if (method != null) {
                        builder.tokenEndpointAuthenticationMethod(method);
                    }
                })
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();
    }

    private static JsonObject validTokenResponse() {
        return JsonObject.builder()
                .set("access_token", "access-token")
                .set("token_type", "Bearer")
                .set("id_token", "id-token")
                .set("refresh_token", "refresh-token")
                .set("expires_in", 3600)
                .set("scope", "openid profile")
                .build();
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

    private record RecordedRequest(String method,
                                   String authorization,
                                   String contentType,
                                   List<String> cacheControl,
                                   Map<String, List<String>> formParameters) {
    }
}
