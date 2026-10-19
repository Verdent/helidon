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

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.pki.Keys;
import io.helidon.common.socket.SocketOptions;
import io.helidon.common.tls.Tls;
import io.helidon.common.tls.TlsClientAuth;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonArray;
import io.helidon.json.JsonBoolean;
import io.helidon.json.JsonNull;
import io.helidon.json.JsonNumber;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.json.JsonString;
import io.helidon.json.JsonValue;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkOctet;
import io.helidon.security.jwt.jwk.JwkRSA;
import io.helidon.security.providers.oidc.next.spi.OidcTenantAdapter;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.WebServerConfig;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;
import io.helidon.webserver.testing.junit5.SetUpServer;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ServerTest
class OidcAuthorizationCodeTokenExchangeTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback?registered=true");
    private static final String CLIENT_ID = "client/id";
    private static final String CLIENT_SECRET =
            "client+secret=value:0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final String AUTHORIZATION_CODE = "authorization-code+value";
    private static final String PKCE_VERIFIER = "pkce-verifier+value";
    private static final String REFRESH_TOKEN = "refresh-token+value";
    private static final String PUSHED_AUTHORIZATION_REQUEST_URI =
            "urn:ietf:params:oauth:request_uri:test-request";
    private static final String CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();
    private static final AtomicReference<String> JWK_SET = new AtomicReference<>();
    private static final AtomicReference<String> HTTPS_METADATA_RESPONSE = new AtomicReference<>();
    private static final AtomicInteger HTTPS_METADATA_REQUESTS = new AtomicInteger();
    private static final AtomicInteger HTTP_METADATA_REQUESTS = new AtomicInteger();
    private static final AtomicInteger TYPED_JWK_REQUESTS = new AtomicInteger();
    private static final AtomicInteger CONVENTIONAL_REQUESTS = new AtomicInteger();
    private static final AtomicInteger MUTUAL_TLS_REQUESTS = new AtomicInteger();
    private static final AtomicBoolean MUTUAL_TLS_CERTIFICATE_PRESENT = new AtomicBoolean();
    private static final AtomicReference<String> USER_INFO_AUTHORIZATION = new AtomicReference<>();

    private static volatile int responseStatus;
    private static volatile String responseBody;
    private static volatile String responseContentType;
    private static volatile String responseCacheControl;
    private static volatile String responsePragma;
    private static volatile int userInfoStatus;
    private static JwkKeys signKeys;
    private static JwkKeys encryptKeys;

    private final URI mutualTlsServerUri;
    private final URI conventionalTlsServerUri;

    private URI tokenEndpointUri;
    private URI mutualTlsTokenEndpointUri;
    private URI pushedAuthorizationRequestEndpointUri;
    private URI mutualTlsPushedAuthorizationRequestEndpointUri;

    OidcAuthorizationCodeTokenExchangeTest(WebServer server) {
        mutualTlsServerUri = URI.create("https://localhost:" + server.port("mtls") + "/");
        conventionalTlsServerUri = URI.create("https://localhost:" + server.port("conventional") + "/");
    }

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        encryptKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-encrypt-jwk.json"))
                .build();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.post("/token", OidcAuthorizationCodeTokenExchangeTest::handleTokenEndpoint);
        routing.post("/par", OidcAuthorizationCodeTokenExchangeTest::handleTokenEndpoint);
        routing.get("/jwks", (_, response) -> {
            TYPED_JWK_REQUESTS.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON).send(JWK_SET.get());
        });
        routing.get("/.well-known/openid-configuration", (_, response) -> {
            HTTP_METADATA_REQUESTS.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON).send("{}");
        });
    }

    @SetUpRoute("mtls")
    static void mutualTlsRouting(HttpRouting.Builder routing) {
        routing.post("/token", (request, response) -> {
            recordMutualTls(request);
            handleTokenEndpoint(request, response);
        });
        routing.post("/par", (request, response) -> {
            recordMutualTls(request);
            handleTokenEndpoint(request, response);
        });
        routing.get("/userinfo", (request, response) -> {
            recordMutualTls(request);
            USER_INFO_AUTHORIZATION.set(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""));
            response.status(userInfoStatus).header(HeaderValues.CONTENT_TYPE_JSON).send("{\"sub\":\"subject\"}");
        });
    }

    @SetUpRoute("conventional")
    static void conventionalTlsRouting(HttpRouting.Builder routing) {
        routing.get("/.well-known/openid-configuration", (_, response) -> {
            HTTPS_METADATA_REQUESTS.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON).send(HTTPS_METADATA_RESPONSE.get());
        });
        routing.get("/jwks", (_, response) -> {
            TYPED_JWK_REQUESTS.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON).send(JWK_SET.get());
        });
        routing.post("/token", (request, response) -> {
            CONVENTIONAL_REQUESTS.incrementAndGet();
            handleTokenEndpoint(request, response);
        });
        routing.post("/par", (request, response) -> {
            CONVENTIONAL_REQUESTS.incrementAndGet();
            handleTokenEndpoint(request, response);
        });
        routing.get("/userinfo", (request, response) -> {
            CONVENTIONAL_REQUESTS.incrementAndGet();
            USER_INFO_AUTHORIZATION.set(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""));
            response.status(userInfoStatus).header(HeaderValues.CONTENT_TYPE_JSON).send("{\"sub\":\"subject\"}");
        });
    }

    @SetUpServer
    static void server(WebServerConfig.Builder builder) {
        builder.putSocket("mtls", socket -> socket.tls(serverTls(TlsClientAuth.REQUIRED)));
        builder.putSocket("conventional", socket -> socket.tls(serverTls(TlsClientAuth.NONE)));
    }

    @BeforeEach
    void setUp(URI serverUri) {
        tokenEndpointUri = serverUri.resolve("token");
        mutualTlsTokenEndpointUri = mutualTlsServerUri.resolve("token");
        // RFC 9126 requires HTTPS for PAR even when the other test endpoints and RP callback use HTTP.
        pushedAuthorizationRequestEndpointUri = conventionalTlsServerUri.resolve("par");
        mutualTlsPushedAuthorizationRequestEndpointUri = mutualTlsServerUri.resolve("par");
        responseStatus = 200;
        responseBody = validTokenResponse().toString();
        responseContentType = "application/json";
        responseCacheControl = "no-store";
        responsePragma = "no-cache";
        userInfoStatus = 200;
        RECORDED_REQUEST.set(null);
        JWK_SET.set(Resource.create("oidc-next-encrypt-public-jwk.json").string());
        CONVENTIONAL_REQUESTS.set(0);
        MUTUAL_TLS_REQUESTS.set(0);
        MUTUAL_TLS_CERTIFICATE_PRESENT.set(false);
        USER_INFO_AUTHORIZATION.set(null);
        HTTPS_METADATA_RESPONSE.set(null);
        HTTPS_METADATA_REQUESTS.set(0);
        HTTP_METADATA_REQUESTS.set(0);
        TYPED_JWK_REQUESTS.set(0);
    }

    @Test
    void authorizationRedirectFormEncodesParametersAndRetainsEndpointQuery(URI serverUri) {
        String clientId = "client/id?mode=a&client_injected=true+literal%£";
        URI redirectionEndpointUri = URI.create(
                "https://rp.example/oidc/callback?channel=a&redirect_injected=b+plus&pct=%25&currency=£");
        List<String> resources = List.of(
                "https://api.example/items?type=a&resource_injected=b+plus&pct=%25&currency=%C2%A3",
                "urn:example:contacts?role=a=b&literal=+");
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(clientId)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(serverUri.resolve("authorize?existing=endpoint%26value"))
                        .tokenEndpointUri(tokenEndpointUri)
                        .jwksUri(serverUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(redirectionEndpointUri)
                        .resources(resources))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .path("/resource")
                .transport("https")
                .build();

        URI location = authenticationRequest(tenant, environment).authorizationUri();

        UriQuery query = UriQuery.create(location);
        assertThat(query.get("existing"), is("endpoint&value"));
        assertThat(query.get("client_id"), is(clientId));
        assertThat(query.getRaw("client_id"),
                   is("client%2Fid%3Fmode%3Da%26client_injected%3Dtrue%2Bliteral%25%C2%A3"));
        assertThat(query.get("redirect_uri"), is(redirectionEndpointUri.toString()));
        assertThat(query.all("resource"), is(resources));
        assertThat(query.contains("client_injected"), is(false));
        assertThat(query.contains("redirect_injected"), is(false));
        assertThat(query.contains("resource_injected"), is(false));
        assertThat(query.contains("pct"), is(false));
        assertThat(query.contains("currency"), is(false));
        assertThat(query.contains("literal"), is(false));
    }

    @Test
    void pushedAuthorizationRedirectFormEncodesRequestUri(URI serverUri) {
        String requestUri = "urn:ietf:params:oauth:request_uri:test?part=a&par_injected=b+plus&pct=%25";
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse(requestUri).toString();
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .webClient(conventionalTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(serverUri.resolve("authorize?existing=endpoint%26value"))
                        .tokenEndpointUri(tokenEndpointUri)
                        .jwksUri(serverUri.resolve("jwks"))
                        .pushedAuthorizationRequestEndpointUri(pushedAuthorizationRequestEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .path("/resource")
                .transport("https")
                .build();

        URI location = authenticationRequest(tenant, environment).authorizationUri();

        UriQuery query = UriQuery.create(location);
        assertThat(query.get("existing"), is("endpoint&value"));
        assertThat(query.get("client_id"), is(CLIENT_ID));
        assertThat(query.getRaw("client_id"), is("client%2Fid"));
        assertThat(query.get("request_uri"), is(requestUri));
        assertThat(query.getRaw("request_uri"),
                   is("urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Atest%3Fpart%3Da"
                              + "%26par_injected%3Db%2Bplus%26pct%3D%2525"));
        assertThat(query.contains("par_injected"), is(false));
        assertThat(query.contains("pct"), is(false));
    }

    @Test
    void pushedAuthorizationRequestPostsAuthorizationRequestParametersAndUsesClientSecretBasic() {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();

        OidcPushedAuthorizationRequestResult result = pushedAuthorizationRequest(confidentialParTenant(),
                                                                                authorizationRequestParameters());

        assertThat(result.succeeded(), is(true));
        OidcPushedAuthorizationResponse parResponse = result.response().orElseThrow();
        assertThat(parResponse.requestUri(), is(PUSHED_AUTHORIZATION_REQUEST_URI));
        assertThat(parResponse.expiresIn(), is(90L));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request, is(notNullValue()));
        assertThat(request.method(), is("POST"));
        assertThat(request.authorization(),
                   is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
        assertThat(request.contentType(), is("application/x-www-form-urlencoded"));
        assertThat(request.formParameters(), is(Map.of("response_type", List.of("code"),
                                                       "client_id", List.of(CLIENT_ID),
                                                       "redirect_uri", List.of(REDIRECTION_ENDPOINT_URI.toString()),
                                                       "scope", List.of("openid profile"),
                                                       "state", List.of("state-value"),
                                                       "nonce", List.of("nonce-value"),
                                                       "prompt", List.of("login consent"),
                                                       "resource", List.of("https://api.example.com",
                                                                           "urn:example:contacts"),
                                                       "code_challenge", List.of("challenge-value"),
                                                       "code_challenge_method", List.of("S256"))));
        assertThat(request.formParameters().containsKey("request_uri"), is(false));
    }

    @Test
    void oversizedReturnUriIsRejectedBeforePushedAuthorizationRequest(URI serverUri) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString()).clientId(CLIENT_ID).clientSecret(CLIENT_SECRET)
                .webClient(conventionalTlsWebClient())
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(serverUri.resolve("authorize"))
                        .tokenEndpointUri(tokenEndpointUri).jwksUri(serverUri.resolve("jwks"))
                        .pushedAuthorizationRequestEndpointUri(pushedAuthorizationRequestEndpointUri).tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(cookies -> cookies.maxChunks(1).password("test-cookie-password"))
                .buildPrototype();
        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder().putTenant("default", tenant)
                                                                .buildPrototype())) {
            AuthenticationResponse response = provider.authenticate(OidcProviderTest.request(null,
                    SecurityEnvironment.builder().targetUri(URI.create("https://rp.example/resource?filter=" + "a".repeat(3000)))
                            .path("/resource").transport("https").build()));
            assertThat(response.statusCode().orElseThrow(), is(414));
            assertThat(CONVENTIONAL_REQUESTS.get(), is(0));
        }
    }

    @Test
    void tenantAdapterCanCustomizeEachTokenGrantAndNormalizeItsResponse() {
        AtomicReference<OidcTenantAdapter.TokenGrant> grantSeen = new AtomicReference<>();
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "token-test";
            }

            @Override
            public String type() {
                return "token-test";
            }

            @Override
            public Parameters tokenRequest(OidcTenantConfig tenant, TokenGrant grant, Parameters parameters) {
                grantSeen.set(grant);
                Map<String, List<String>> values = parameters.toMap();
                values.put("vendor_parameter", List.of("specific-value"));
                return Parameters.create("adapted-token-form", values);
            }

            @Override
            public JsonObject tokenResponse(OidcTenantConfig tenant, TokenGrant grant, JsonObject response) {
                assertThat(grant, is(grantSeen.get()));
                return JsonObject.builder().from(response).set("access_token", "adapted-access-token").build();
            }
        };
        OidcTenantConfig tenant = OidcTenantConfig.builder().from(confidentialTenant()).adapter(adapter).buildPrototype();

        OidcTokenEndpointResult codeResult = exchange(tenant, PKCE_VERIFIER);
        assertThat(codeResult.succeeded(), is(true));
        assertThat(codeResult.tokenResponse().orElseThrow().accessToken(), is("adapted-access-token"));
        assertThat(RECORDED_REQUEST.get().formParameters().get("vendor_parameter"), is(List.of("specific-value")));
        assertThat(grantSeen.get(), is(OidcTenantAdapter.TokenGrant.AUTHORIZATION_CODE));

        responseBody = validRefreshResponse().toString();
        OidcTokenEndpointResult refreshResult = refresh(tenant, REFRESH_TOKEN);
        assertThat(refreshResult.succeeded(), is(true));
        assertThat(refreshResult.tokenResponse().orElseThrow().accessToken(), is("adapted-access-token"));
        assertThat(RECORDED_REQUEST.get().formParameters().get("vendor_parameter"), is(List.of("specific-value")));
        assertThat(grantSeen.get(), is(OidcTenantAdapter.TokenGrant.REFRESH_TOKEN));

        OidcEndpointClient client = OidcTenantContext.ready("default", tenant).endpointClient();
        responseBody = JsonObject.builder().set("access_token", "original-client-token")
                .set("token_type", "Bearer").set("expires_in", 60).build().toString();
        OidcTokenEndpointResult clientCredentials = client.clientCredentialsToken(Optional.empty(), List.of());
        assertThat(clientCredentials.succeeded(), is(true));
        assertThat(clientCredentials.tokenResponse().orElseThrow().accessToken(), is("adapted-access-token"));
        assertThat(grantSeen.get(), is(OidcTenantAdapter.TokenGrant.CLIENT_CREDENTIALS));

        responseBody = JsonObject.builder().set("access_token", "original-exchanged-token")
                .set("issued_token_type", OidcTokenExchangeResponse.ACCESS_TOKEN_TYPE)
                .set("token_type", "Bearer").set("expires_in", 60).build().toString();
        OidcTokenExchangeResult tokenExchange = client.tokenExchange("subject-token", Optional.empty(),
                                                                      Optional.empty(), Optional.empty());
        assertThat(tokenExchange.succeeded(), is(true));
        assertThat(tokenExchange.tokenResponse().orElseThrow().accessToken(), is("adapted-access-token"));
        assertThat(RECORDED_REQUEST.get().formParameters().get("vendor_parameter"), is(List.of("specific-value")));
        assertThat(grantSeen.get(), is(OidcTenantAdapter.TokenGrant.TOKEN_EXCHANGE));
    }

    @Test
    void pushedAuthorizationRequestRejectsHttpSelectedFromProgrammaticMetadata(URI serverUri) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
        OidcProviderMetadata metadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("pushed_authorization_request_endpoint", serverUri.resolve("par").toString())
                .build());

        // Even metadata supplied directly to a ready context must not send client credentials over HTTP.
        OidcPushedAuthorizationRequestResult result = OidcTenantContext.ready("default", tenant, metadata)
                .endpointClient()
                .pushedAuthorizationRequest(authorizationRequestParameters());

        assertThat(result.succeeded(), is(false));
        assertThat(result.description(), is("Pushed Authorization Request Endpoint must use https"));
        assertThat(RECORDED_REQUEST.get(), is(nullValue()));
    }

    @Test
    void pushedAuthorizationRequestAccepts201WithCustomReasonPhrase() throws Exception {
        assertPushedAuthorizationRequestWithReasonPhrase("Request Stored");
    }

    @Test
    void pushedAuthorizationRequestAccepts201WithoutReasonPhrase() throws Exception {
        assertPushedAuthorizationRequestWithReasonPhrase("");
    }

    @Test
    void pushedAuthorizationRequestWithClientSecretPostDoesNotDuplicateClientId() {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();

        OidcPushedAuthorizationRequestResult result = pushedAuthorizationRequest(
                confidentialParTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_POST),
                authorizationRequestParameters());

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters().get("client_id"), is(List.of(CLIENT_ID)));
        assertThat(request.formParameters().get("client_secret"), is(List.of(CLIENT_SECRET)));
    }

    @Test
    void pushedAuthorizationRequestWithPrivateKeyJwtUsesIssuerAsClientAssertionAudience() {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();

        OidcPushedAuthorizationRequestResult result = pushedAuthorizationRequest(privateKeyJwtParTenant(),
                                                                                authorizationRequestParameters());

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.formParameters().get("client_assertion_type"), is(List.of(CLIENT_ASSERTION_TYPE)));
        assertThat(request.formParameters().get("client_id"), is(List.of(CLIENT_ID)));

        String assertion = request.formParameters().get("client_assertion").getFirst();
        SignedJwt signedJwt = SignedJwt.parseToken(assertion);
        signedJwt.verifySignature(signKeys).checkValid();
        assertThat(signedJwt.getJwt().issuer().orElse(""), is(CLIENT_ID));
        assertThat(signedJwt.getJwt().subject().orElse(""), is(CLIENT_ID));
        assertThat(signedJwt.getJwt().audience().orElseThrow(), is(List.of(ISSUER.toString())));
    }

    @Test
    void staticPushedAuthorizationRequestEndpointDoesNotOverrideWellKnownMutualTlsAlias() {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();
        URI staticPushedAuthorizationRequestEndpointUri = conventionalTlsServerUri.resolve("unused-par");
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(mutualTlsTokenEndpointUri)
                        .pushedAuthorizationRequestEndpointUri(staticPushedAuthorizationRequestEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
        OidcProviderMetadata wellKnownMetadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("authorization_endpoint", AUTHORIZATION_ENDPOINT_URI.toString())
                .set("token_endpoint", conventionalTlsServerUri.resolve("token").toString())
                .set("pushed_authorization_request_endpoint",
                     conventionalTlsServerUri.resolve("well-known-par").toString())
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("token_endpoint", mutualTlsTokenEndpointUri.toString())
                        .set("pushed_authorization_request_endpoint",
                             mutualTlsPushedAuthorizationRequestEndpointUri.toString())
                        .build())
                .build());
        OidcProviderMetadata metadata = OidcProviderMetadata.fromStaticConfig(tenant)
                .mergeWellKnownMetadata(wellKnownMetadata);

        assertThat(metadata.pushedAuthorizationRequestEndpointUri(),
                   is(Optional.of(staticPushedAuthorizationRequestEndpointUri)));
        assertThat(metadata.mutualTlsPushedAuthorizationRequestEndpointUri(),
                   is(Optional.of(mutualTlsPushedAuthorizationRequestEndpointUri)));

        OidcPushedAuthorizationRequestResult result = OidcTenantContext.ready("default", tenant, metadata)
                .endpointClient()
                .pushedAuthorizationRequest(authorizationRequestParameters());

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters().get("client_id"), is(List.of(CLIENT_ID)));
    }

    @Test
    void bindingOnlyClientAuthenticationMethodsPreferRealMutualTlsTokenAlias() {
        for (OidcClientAuthenticationMethod method : List.of(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                                              OidcClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                                              OidcClientAuthenticationMethod.NONE)) {
            CONVENTIONAL_REQUESTS.set(0);
            MUTUAL_TLS_REQUESTS.set(0);
            MUTUAL_TLS_CERTIFICATE_PRESENT.set(false);
            OidcTenantConfig tenant = outboundMutualTlsTenant(method, true);
            OidcProviderMetadata metadata = providerMetadata(tenant, true);

            OidcTokenEndpointResult result = OidcTenantContext.ready("default", tenant, metadata)
                    .endpointClient()
                    .exchangeAuthorizationCode(AUTHORIZATION_CODE,
                                               REDIRECTION_ENDPOINT_URI,
                                               Optional.of(PKCE_VERIFIER));

            assertThat(method.toString(), result.succeeded(), is(true));
            assertThat(method.toString(), MUTUAL_TLS_REQUESTS.get(), is(1));
            assertThat(method.toString(), CONVENTIONAL_REQUESTS.get(), is(0));
            assertThat(method.toString(), MUTUAL_TLS_CERTIFICATE_PRESENT.get(), is(true));
            RecordedRequest request = RECORDED_REQUEST.get();
            assertThat(request.formParameters().get("grant_type"), is(List.of("authorization_code")));
            if (method == OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC) {
                assertThat(request.authorization(),
                           is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
                assertThat(request.formParameters().containsKey("client_assertion"), is(false));
            } else if (method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT) {
                assertThat(request.authorization(), is(""));
                assertThat(request.formParameters().get("client_assertion_type"),
                           is(List.of(CLIENT_ASSERTION_TYPE)));
            } else {
                assertThat(request.authorization(), is(""));
                assertThat(request.formParameters().get("client_id"), is(List.of(CLIENT_ID)));
                assertThat(request.formParameters().containsKey("client_assertion"), is(false));
            }
        }
    }

    @Test
    void refreshedAndOutboundTokensUseTheSameMutualTlsAlias() {
        OidcTenantConfig tenant = outboundMutualTlsTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);
        OidcEndpointClient client = OidcTenantContext.ready("default", tenant, providerMetadata(tenant, true))
                .endpointClient();
        responseBody = validRefreshResponse().toString();

        OidcTokenEndpointResult refresh = client.refreshAccessToken(REFRESH_TOKEN);

        assertThat(refresh.succeeded(), is(true));
        responseBody = JsonObject.builder()
                .set("access_token", "client-token")
                .set("token_type", "Bearer")
                .set("expires_in", 60)
                .build()
                .toString();
        OidcTokenEndpointResult clientCredentials = client.clientCredentialsToken(Optional.empty(), List.of());

        assertThat(clientCredentials.succeeded(), is(true));
        responseBody = JsonObject.builder()
                .set("access_token", "exchanged-token")
                .set("issued_token_type", OidcTokenExchangeResponse.ACCESS_TOKEN_TYPE)
                .set("token_type", "Bearer")
                .set("expires_in", 60)
                .build()
                .toString();
        OidcTokenExchangeResult tokenExchange = client.tokenExchange("subject-token",
                                                                      Optional.empty(),
                                                                      Optional.empty(),
                                                                      Optional.empty());

        assertThat(tokenExchange.succeeded(), is(true));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(3));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(0));
        assertThat(MUTUAL_TLS_CERTIFICATE_PRESENT.get(), is(true));
        assertThat(RECORDED_REQUEST.get().formParameters().get("grant_type"),
                   is(List.of("urn:ietf:params:oauth:grant-type:token-exchange")));
    }

    @Test
    void bindingOnlyPrefersMutualTlsParAliasEvenWithStaticConventionalEndpoint() {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();
        OidcTenantConfig tenant = outboundMutualTlsTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);

        OidcPushedAuthorizationRequestResult result = OidcTenantContext.ready("default", tenant,
                                                                                 providerMetadata(tenant, true))
                .endpointClient()
                .pushedAuthorizationRequest(authorizationRequestParameters());

        assertThat(result.succeeded(), is(true));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(1));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(0));
        assertThat(MUTUAL_TLS_CERTIFICATE_PRESENT.get(), is(true));
        assertThat(RECORDED_REQUEST.get().authorization(),
                   is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
    }

    @Test
    void advertisedOpUserInfoAliasUsesTheClientCertificateAndBearerToken() {
        for (OidcClientAuthenticationMethod method : List.of(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                                              OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)) {
            CONVENTIONAL_REQUESTS.set(0);
            MUTUAL_TLS_REQUESTS.set(0);
            MUTUAL_TLS_CERTIFICATE_PRESENT.set(false);
            OidcTenantConfig tenant = outboundMutualTlsTenant(method,
                                                              method == OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC);

            OidcUserInfoEndpointResult result = OidcTenantContext.ready("default", tenant,
                                                                          providerMetadata(tenant, true))
                    .endpointClient()
                    .userInfo("opaque-access-token");

            assertThat(method.toString(), result.succeeded(), is(true));
            assertThat(result.json().orElseThrow().stringValue("sub").orElseThrow(), is("subject"));
            assertThat(USER_INFO_AUTHORIZATION.get(), is("Bearer opaque-access-token"));
            assertThat(method.toString(), MUTUAL_TLS_REQUESTS.get(), is(1));
            assertThat(method.toString(), CONVENTIONAL_REQUESTS.get(), is(0));
            assertThat(method.toString(), MUTUAL_TLS_CERTIFICATE_PRESENT.get(), is(true));
        }
    }

    @Test
    void configuredTlsCredentialsWithoutOutboundIntentDoNotSelectAliases() {
        OidcTenantConfig tenant = outboundMutualTlsTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC, false);
        OidcEndpointClient client = OidcTenantContext.ready("default", tenant, providerMetadata(tenant, true))
                .endpointClient();

        OidcTokenEndpointResult token = client.exchangeAuthorizationCode(AUTHORIZATION_CODE,
                                                                         REDIRECTION_ENDPOINT_URI,
                                                                         Optional.of(PKCE_VERIFIER));
        OidcUserInfoEndpointResult userInfo = client.userInfo("ordinary-access-token");

        assertThat(token.succeeded(), is(true));
        assertThat(userInfo.succeeded(), is(true));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(2));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(0));
        assertThat(USER_INFO_AUTHORIZATION.get(), is("Bearer ordinary-access-token"));
    }

    @Test
    void absentMutualTlsAliasUsesTheConventionalHttpsEndpoint() {
        OidcTenantConfig tenant = outboundMutualTlsTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);

        OidcTokenEndpointResult result = OidcTenantContext.ready("default", tenant, providerMetadata(tenant, false))
                .endpointClient()
                .exchangeAuthorizationCode(AUTHORIZATION_CODE, REDIRECTION_ENDPOINT_URI, Optional.of(PKCE_VERIFIER));

        assertThat(result.succeeded(), is(true));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(1));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(0));
    }

    @Test
    void absentOpUserInfoAliasUsesTheConventionalHttpsEndpoint() {
        OidcTenantConfig tenant = outboundMutualTlsTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);

        OidcUserInfoEndpointResult result = OidcTenantContext.ready("default", tenant, providerMetadata(tenant, false))
                .endpointClient()
                .userInfo("opaque-access-token");

        assertThat(result.succeeded(), is(true));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(1));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(0));
    }

    @Test
    void failedMutualTlsTokenAliasIsNotRetriedAtTheConventionalEndpoint() {
        responseStatus = 503;
        responseBody = JsonObject.builder().set("error", "temporarily_unavailable").build().toString();
        OidcTenantConfig tenant = outboundMutualTlsTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);

        OidcTokenEndpointResult result = OidcTenantContext.ready("default", tenant, providerMetadata(tenant, true))
                .endpointClient()
                .exchangeAuthorizationCode(AUTHORIZATION_CODE, REDIRECTION_ENDPOINT_URI, Optional.of(PKCE_VERIFIER));

        assertThat(result.succeeded(), is(false));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(1));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(0));
    }

    @Test
    void failedMutualTlsParAliasIsNotRetriedAtTheConventionalEndpoint() {
        responseStatus = 503;
        responseBody = JsonObject.builder().set("error", "temporarily_unavailable").build().toString();
        OidcTenantConfig tenant = outboundMutualTlsTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);

        OidcPushedAuthorizationRequestResult result = OidcTenantContext.ready("default", tenant,
                                                                                 providerMetadata(tenant, true))
                .endpointClient()
                .pushedAuthorizationRequest(authorizationRequestParameters());

        assertThat(result.succeeded(), is(false));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(1));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(0));
    }

    @Test
    void failedOpUserInfoAliasIsNotRetriedAtTheConventionalEndpoint() {
        userInfoStatus = 503;
        OidcTenantConfig tenant = outboundMutualTlsTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);

        OidcUserInfoEndpointResult result = OidcTenantContext.ready("default", tenant,
                                                                      providerMetadata(tenant, true))
                .endpointClient()
                .userInfo("opaque-access-token");

        assertThat(result.succeeded(), is(false));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(1));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(0));
        assertThat(USER_INFO_AUTHORIZATION.get(), is("Bearer opaque-access-token"));
    }

    @Test
    void discoveredAliasOnlyParEndpointIsUsedByAutoAuthorizationRequests() {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();
        HTTPS_METADATA_RESPONSE.set(localWellKnownMetadata()
                                            .set("mtls_endpoint_aliases", JsonObject.builder()
                                                    .set("token_endpoint", mutualTlsServerUri.resolve("token").toString())
                                                    .set("pushed_authorization_request_endpoint",
                                                         mutualTlsServerUri.resolve("par").toString())
                                                    .build())
                                            .build()
                                            .toString());
        OidcTenantConfig tenant = discoveredMutualTlsTenant(false, Optional.empty());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .path("/resource")
                .transport("https")
                .build();

        URI redirect = authenticationRequest(tenant, environment).authorizationUri();

        assertThat(UriQuery.create(redirect).get("request_uri"), is(PUSHED_AUTHORIZATION_REQUEST_URI));
        assertThat(HTTPS_METADATA_REQUESTS.get(), is(1));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(1));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(0));
        assertThat(MUTUAL_TLS_CERTIFICATE_PRESENT.get(), is(true));
    }

    @Test
    void discoveredUserInfoAliasWithoutTopLevelEndpointIsUsable() {
        HTTPS_METADATA_RESPONSE.set(localWellKnownMetadata()
                                            .set("mtls_endpoint_aliases", JsonObject.builder()
                                                    .set("token_endpoint", mutualTlsServerUri.resolve("token").toString())
                                                    .set("userinfo_endpoint", mutualTlsServerUri.resolve("userinfo").toString())
                                                    .build())
                                            .build()
                                            .toString());
        OidcTenantConfig tenant = discoveredMutualTlsTenant(true, Optional.empty());

        OidcTenantContext context = OidcTenantContextFactory.create().create("default", tenant);

        assertThat(context.failureCause().map(Throwable::toString).orElse("ready"), context.ready(), is(true));
        assertThat(context.metadata().userInfoEndpointUri().isEmpty(), is(true));
        assertThat(context.metadata().userInfoEndpointUri(true),
                   is(Optional.of(mutualTlsServerUri.resolve("userinfo"))));
        OidcUserInfoEndpointResult result = context.endpointClient().userInfo("certificate-bound-access-token");
        assertThat(result.succeeded(), is(true));
        assertThat(USER_INFO_AUTHORIZATION.get(), is("Bearer certificate-bound-access-token"));
        assertThat(HTTPS_METADATA_REQUESTS.get(), is(1));
        assertThat(MUTUAL_TLS_REQUESTS.get(), is(1));
        assertThat(CONVENTIONAL_REQUESTS.get(), is(0));
        assertThat(MUTUAL_TLS_CERTIFICATE_PRESENT.get(), is(true));
    }

    @Test
    void insecureOrFragmentedDiscoveredUserInfoAliasFailsBeforeBearerUse() {
        for (String alias : List.of("http://issuer.example/userinfo",
                                    mutualTlsServerUri.resolve("userinfo").toString() + "#fragment")) {
            HTTPS_METADATA_RESPONSE.set(localWellKnownMetadata()
                                                .set("mtls_endpoint_aliases", JsonObject.builder()
                                                        .set("token_endpoint",
                                                             mutualTlsServerUri.resolve("token").toString())
                                                        .set("userinfo_endpoint", alias)
                                                        .build())
                                                .build()
                                                .toString());
            OidcTenantConfig tenant = discoveredMutualTlsTenant(true, Optional.empty());

            OidcTenantContext context = OidcTenantContextFactory.create().create("default", tenant);

            assertThat(alias, context.state(), is(OidcTenantState.FAILED));
            assertThat(context.failureCause().orElseThrow().getMessage(), containsString("user-info-endpoint-uri"));
            assertThat(context.failureCause().orElseThrow().getMessage(),
                       containsString(alias.startsWith("http:") ? "must use https" : "fragment"));
            assertThat(MUTUAL_TLS_REQUESTS.get(), is(0));
            assertThat(CONVENTIONAL_REQUESTS.get(), is(0));
        }
    }

    @Test
    void outboundMutualTlsRejectsHttpDiscoveryBeforeTheInitialRequest(URI serverUri) {
        URI httpWellKnown = serverUri.resolve(".well-known/openid-configuration");
        OidcTenantConfig tenant = discoveredMutualTlsTenant(false, Optional.of(httpWellKnown));

        OidcTenantContext context = OidcTenantContextFactory.create().create("default", tenant);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("well-known-uri must use https"));
        assertThat(HTTP_METADATA_REQUESTS.get(), is(0));
        assertThat(HTTPS_METADATA_REQUESTS.get(), is(0));
    }

    @Test
    void outboundMutualTlsRejectsHttpDeferredDiscoveryBeforeTheRequest(URI serverUri) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(conventionalIssuer())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .outboundMutualTls(true)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.wellKnownUri(serverUri.resolve(".well-known/openid-configuration"))
                        .tlsRequired(false))
                .buildPrototype();
        OidcTenantContext context = OidcTenantContext.ready("default", tenant);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> new OidcOutboundMetadataResolver().clientCredentialsEndpointClient(context));

        assertThat(failure.getMessage(), containsString("well-known-uri must use https"));
        assertThat(HTTP_METADATA_REQUESTS.get(), is(0));
    }

    @Test
    void pushedAuthorizationRequestRejectsInvalidSuccessfulResponse() {
        responseStatus = 201;
        responseBody = JsonObject.builder()
                .set("request_uri", PUSHED_AUTHORIZATION_REQUEST_URI)
                .build()
                .toString();

        OidcPushedAuthorizationRequestResult result = pushedAuthorizationRequest(confidentialParTenant(),
                                                                                authorizationRequestParameters());

        assertThat(result.succeeded(), is(false));
        assertThat(result.description(), is("Pushed Authorization Request Endpoint response is invalid"));
    }

    @Test
    void pushedAuthorizationRequestDoesNotAccept202AsSuccess() {
        responseStatus = 202;
        responseBody = validPushedAuthorizationResponse().toString();

        OidcPushedAuthorizationRequestResult result = pushedAuthorizationRequest(confidentialParTenant(),
                                                                                  authorizationRequestParameters());

        assertThat(result.succeeded(), is(false));
        assertThat(result.response(), is(Optional.empty()));
    }

    @Test
    void pushedAuthorizationRequestErrorResponseIsParsed() {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid_request")
                .set("error_description", "redirect_uri is invalid")
                .set("error_uri", "https://issuer.example/errors/invalid-request")
                .build()
                .toString();

        OidcPushedAuthorizationRequestResult result = pushedAuthorizationRequest(confidentialParTenant(),
                                                                                authorizationRequestParameters());

        assertThat(result.succeeded(), is(false));
        assertThat(result.errorResponse(), is(true));
        OidcTokenErrorResponse error = result.error().orElseThrow();
        assertThat(error.error(), is("invalid_request"));
        assertThat(error.errorDescription().orElse(""), is("redirect_uri is invalid"));
        assertThat(error.errorUri().orElse(""), is("https://issuer.example/errors/invalid-request"));
    }

    @Test
    void requestObjectRejectsPublicOnlySigningJwk() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantContext.ready("default", OidcTenantConfig.builder()
                                                               .issuer(ISSUER.toString())
                                                               .clientId(CLIENT_ID)
                                                               .clientSecret(CLIENT_SECRET)
                                                               .endpoints(it -> it
                                                                       .authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                                                                       .tokenEndpointUri(tokenEndpointUri)
                                                                       .tlsRequired(false))
                                                               .authorizationCode(it -> it
                                                                       .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                                                                       .requestObject(requestObject -> requestObject
                                                                               .mode(OidcRequestObjectMode.REQUIRED)
                                                                               .signingJwk(jwk -> jwk.resourcePath(
                                                                                       "oidc-next-sign-public-jwk.json"))
                                                                               .signingKeyId("sign-rsa")
                                                                               .signingAlgorithm("RS256")))
                                                               .cookies(it -> it.password("test-cookie-password"))
                                                               .buildPrototype()));

        assertThat(thrown.getMessage(), containsString("authorization-code.request-object.signing-jwk"));
    }

    @Test
    void authorizationCodeFlowInitiationUsesPushedAuthorizationRequest(URI serverUri) {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .webClient(conventionalTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(serverUri.resolve("authorize"))
                        .tokenEndpointUri(tokenEndpointUri)
                        .jwksUri(serverUri.resolve("jwks"))
                        .pushedAuthorizationRequestEndpointUri(pushedAuthorizationRequestEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile"))
                        .prompts(List.of("login"))
                        .resources(List.of("https://api.example.com")))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                            .putTenant("default", tenant)
                                                            .buildPrototype());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .path("/resource")
                .transport("https")
                .build();

        AuthenticationResponse response = provider.authenticate(OidcProviderTest.request(null, environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
        assertThat(response.statusCode().orElse(-1), is(303));
        URI location = URI.create(response.responseHeaders().get("Location").getFirst());
        assertThat(location.getPath(), is("/authorize"));
        UriQuery query = UriQuery.create(location);
        assertThat(query.get("client_id"), is(CLIENT_ID));
        assertThat(query.get("request_uri"), is(PUSHED_AUTHORIZATION_REQUEST_URI));
        assertThat(query.contains("response_type"), is(false));
        assertThat(query.contains("scope"), is(false));
        assertThat(query.contains("state"), is(false));
        assertThat(query.contains("nonce"), is(false));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.formParameters().get("response_type"), is(List.of("code")));
        assertThat(request.formParameters().get("scope"), is(List.of("openid profile")));
        assertThat(request.formParameters().get("prompt"), is(List.of("login")));
        assertThat(request.formParameters().get("resource"), is(List.of("https://api.example.com")));
        assertThat(request.formParameters().containsKey("state"), is(true));
        assertThat(request.formParameters().containsKey("nonce"), is(true));
        assertThat(request.formParameters().containsKey("request_uri"), is(false));
    }

    @Test
    void authorizationCodeFlowInitiationCanUseSignedRequestObjectWithPushedAuthorizationRequest(URI serverUri) {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .webClient(conventionalTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(serverUri.resolve("authorize"))
                        .tokenEndpointUri(tokenEndpointUri)
                        .jwksUri(serverUri.resolve("jwks"))
                        .pushedAuthorizationRequestEndpointUri(pushedAuthorizationRequestEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile"))
                        .prompts(List.of("login"))
                        .resources(List.of("https://api.example.com", "urn:example:contacts"))
                                .requestObject(requestObject -> requestObject.mode(OidcRequestObjectMode.REQUIRED)
                                        .signingJwk(jwk -> jwk.resourcePath("oidc-next-sign-jwk.json"))
                                        .signingKeyId("sign-rsa")
                                        .signingAlgorithm("RS512")))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                            .putTenant("default", tenant)
                                                            .buildPrototype());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .path("/resource")
                .transport("https")
                .build();

        AuthenticationResponse response = provider.authenticate(OidcProviderTest.request(null, environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
        URI location = URI.create(response.responseHeaders().get("Location").getFirst());
        UriQuery query = UriQuery.create(location);
        assertThat(query.get("client_id"), is(CLIENT_ID));
        assertThat(query.get("request_uri"), is(PUSHED_AUTHORIZATION_REQUEST_URI));
        assertThat(query.contains("request"), is(false));
        assertThat(query.contains("state"), is(false));
        assertThat(query.contains("nonce"), is(false));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(),
                   is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
        assertThat(request.formParameters().keySet(), is(Set.of("request")));

        String requestObject = request.formParameters().get("request").getFirst();
        String[] requestObjectParts = requestObject.split("\\.", -1);
        assertThat(requestObjectParts.length, is(3));
        JsonObject requestObjectHeader = JsonParser.create(Base64.getUrlDecoder().decode(requestObjectParts[0]))
                .readJsonObject();
        JsonObject requestObjectPayload = JsonParser.create(Base64.getUrlDecoder().decode(requestObjectParts[1]))
                .readJsonObject();
        SignedJwt signedRequestObject = SignedJwt.parseToken(requestObject);
        assertThat(OidcJoseKeyPolicy.verifySignature(signedRequestObject,
                                                     signedRequestObject.getJwt(),
                                                     signKeys).isValid(),
                   is(true));
        assertThat(requestObjectHeader.stringValue("alg").orElse(""), is("RS512"));
        assertThat(requestObjectHeader.stringValue("typ").orElse(""), is("JWT"));
        assertThat(requestObjectHeader.stringValue("kid").orElse(""), is("sign-rsa"));
        assertThat(requestObjectPayload.stringValue("iss").orElse(""), is(CLIENT_ID));
        assertThat(requestObjectPayload.stringValue("response_type").orElse(""), is("code"));
        assertThat(requestObjectPayload.stringValue("client_id").orElse(""), is(CLIENT_ID));
        assertThat(requestObjectPayload.stringValue("scope").orElse(""), is("openid profile"));
        assertThat(requestObjectPayload.containsKey("state"), is(true));
        assertThat(requestObjectPayload.containsKey("nonce"), is(true));
        assertThat(requestObjectPayload.containsKey("code_challenge"), is(true));
        assertThat(requestObjectPayload.stringValue("code_challenge_method").orElse(""), is("S256"));
        assertThat(requestObjectPayload.value("aud").orElseThrow()
                           .asArray()
                           .values()
                           .stream()
                           .map(value -> value.asString().value())
                           .toList(),
                   is(List.of(ISSUER.toString())));
        assertThat(requestObjectPayload.stringValue("redirect_uri").orElse(""), is(REDIRECTION_ENDPOINT_URI.toString()));
        assertThat(requestObjectPayload.stringValue("prompt").orElse(""), is("login"));
        assertThat(requestObjectPayload.value("resource").orElseThrow()
                           .asArray()
                           .values()
                           .stream()
                           .map(value -> value.asString().value())
                           .toList(),
                   is(List.of("https://api.example.com", "urn:example:contacts")));
        assertThat(requestObjectPayload.containsKey("request"), is(false));
        assertThat(requestObjectPayload.containsKey("request_uri"), is(false));
    }

    @Test
    void tenantAdapterValuesAreStoredAndSignedInsideThePushedRequestObject(URI serverUri) {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "jar-par-test";
            }

            @Override
            public String type() {
                return "jar-par-test";
            }

            @Override
            public OidcAuthorizationParameters authorizationRequest(OidcTenantConfig tenant,
                                                                    String tenantId,
                                                                    SecurityEnvironment environment,
                                                                    OidcAuthorizationParameters parameters) {
                OidcAuthorizationParameters.Builder values = OidcAuthorizationParameters.builder(parameters);
                values.putParameter("state",
                        List.of(JsonString.create("vendor-"
                                + OidcAuthorizationParameterSupport.requiredString(parameters, "state"))));
                values.putParameter("nonce",
                        List.of(JsonString.create("vendor-"
                                + OidcAuthorizationParameterSupport.requiredString(parameters, "nonce"))));
                values.putParameter("login_hint", List.of(JsonString.create("alice@example.org")));
                return values.buildPrototype();
            }
        };
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .webClient(conventionalTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(serverUri.resolve("authorize"))
                        .tokenEndpointUri(tokenEndpointUri)
                        .jwksUri(serverUri.resolve("jwks"))
                        .pushedAuthorizationRequestEndpointUri(pushedAuthorizationRequestEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .requestObject(requestObject -> requestObject.mode(OidcRequestObjectMode.REQUIRED)
                                .signingJwk(jwk -> jwk.resourcePath("oidc-next-sign-jwk.json"))
                                .signingKeyId("sign-rsa")))
                .cookies(it -> it.password("test-cookie-password"))
                .adapter(adapter)
                .buildPrototype();
        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("default", tenant).buildPrototype())) {
            AuthenticationResponse response = provider.authenticate(OidcProviderTest.request(null,
                    SecurityEnvironment.builder().targetUri(URI.create("https://rp.example/resource"))
                            .path("/resource").transport("https").build()));
            assertThat(response.statusCode().orElse(-1), is(303));
            UriQuery redirect = UriQuery.create(URI.create(response.responseHeaders().get("Location").getFirst()));
            assertThat(redirect.get("request_uri"), is(PUSHED_AUTHORIZATION_REQUEST_URI));
            assertThat(redirect.contains("login_hint"), is(false));

            RecordedRequest request = RECORDED_REQUEST.get();
            assertThat(request.formParameters().keySet(), is(Set.of("request")));
            SignedJwt signed = SignedJwt.parseToken(request.formParameters().get("request").getFirst());
            assertThat(OidcJoseKeyPolicy.verifySignature(signed, signed.getJwt(), signKeys).isValid(), is(true));
            JsonObject claims = JsonObject.create(signed.getJwt().payloadClaimsJson());
            assertThat(claims.stringValue("login_hint").orElse(""), is("alice@example.org"));
            SetCookie cookie = SetCookie.parse(response.responseHeaders().get("Set-Cookie").getFirst());
            OidcAuthenticationRequestState state = OidcCookieStateHandler.create("default", tenant)
                    .readAuthenticationRequestState(cookie.value(), Instant.now()).orElseThrow();
            assertThat(claims.stringValue("state").orElse(""), is(state.state()));
            assertThat(claims.stringValue("nonce").orElse(""), is(state.nonce()));
        }
    }

    @Test
    void typedAuthorizationValuesSurviveAllTransports(URI serverUri) throws Exception {
        JsonObject requestedClaims = JsonObject.builder().set("userinfo", JsonObject.builder()
                .set("email", JsonObject.builder().set("essential", true).build())
                .set("nickname", JsonNull.instance()).build()).build();
        JsonArray details = JsonArray.create(List.of(JsonObject.builder().set("type", "payment").set("amount", 10).build()));
        for (String mode : List.of("QUERY", "PAR", "JAR", "JAR_PAR", "JWE", "JWE_PAR")) {
            RECORDED_REQUEST.set(null);
            responseStatus = 201;
            responseBody = validPushedAuthorizationResponse().toString();
            OidcTenantAdapter adapter = new OidcTenantAdapter() {
                @Override
                public String name() {
                    return "typed-authorization-test";
                }

                @Override
                public String type() {
                    return "typed-authorization-test";
                }

                @Override
                public OidcAuthorizationParameters authorizationRequest(OidcTenantConfig tenant,
                                                                        String tenantId,
                                                                        SecurityEnvironment environment,
                                                                        OidcAuthorizationParameters parameters) {
                    return OidcAuthorizationParameters.builder(parameters)
                            .addParameter("max_age", JsonNumber.create(300))
                            .addParameter("claims", requestedClaims).addParameter("authorization_details", details)
                            .addParameter("login_hint", JsonString.create("000300"))
                            .addParameter("opaque_json", JsonString.create("{\"a\":1}"))
                            .addParameter("name", JsonString.create("Alice"))
                            .addParameter("email_verified", JsonBoolean.create(true))
                            .addParameter("custom_null", JsonNull.instance())
                            .addParameter("precise", JsonNumber.create(new BigDecimal("9007199254740993.25")))
                            .buildPrototype();
                }
            };
            OidcTenantConfig tenant = typedAuthorizationTenant(serverUri, mode, adapter);
            try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder().putTenant("default", tenant)
                    .buildPrototype())) {
                AuthenticationResponse response = provider.authenticate(OidcProviderTest.request(null,
                        SecurityEnvironment.builder().targetUri(URI.create("https://rp.example/resource"))
                                .path("/resource").transport("https").build()));
                assertThat(mode, response.statusCode().orElseThrow(), is(303));
                UriQuery query = UriQuery.create(URI.create(response.responseHeaders().get("Location").getFirst()));
                boolean par = mode.endsWith("PAR");
                Parameters wire = par ? Parameters.create("pushed", RECORDED_REQUEST.get().formParameters()) : query;
                if (mode.equals("QUERY") || mode.equals("PAR")) {
                    assertThat(wire.get("max_age"), is("300"));
                    assertThat(wire.get("claims"), is(requestedClaims.toString()));
                    assertThat(wire.get("authorization_details"), is(details.toString()));
                    assertThat(wire.all("resource"), is(List.of("https://api.example/one", "urn:example:two")));
                    assertThat(wire.get("login_hint"), is("000300"));
                    assertThat(wire.get("name"), is("Alice"));
                } else {
                    JsonObject payload = typedRequestPayload(wire.get("request"));
                    assertThat(payload.numberValue("max_age"), is(Optional.of(BigDecimal.valueOf(300))));
                    assertThat(payload.objectValue("claims"), is(Optional.of(requestedClaims)));
                    assertThat(payload.arrayValue("authorization_details"), is(Optional.of(details)));
                    assertThat(payload.stringValue("login_hint"), is(Optional.of("000300")));
                    assertThat(payload.stringValue("opaque_json"), is(Optional.of("{\"a\":1}")));
                    assertThat(payload.stringValue("name"), is(Optional.of("Alice")));
                    assertThat(payload.booleanValue("email_verified"), is(Optional.of(true)));
                    assertThat(payload.value("custom_null"), is(Optional.of(JsonNull.instance())));
                    assertThat(payload.numberValue("precise"), is(Optional.of(new BigDecimal("9007199254740993.25"))));
                    assertThat(payload.arrayValue("resource").orElseThrow().values(),
                               is(List.of(JsonString.create("https://api.example/one"), JsonString.create("urn:example:two"))));
                    Map<String, List<String>> cookies = new LinkedHashMap<>();
                    response.responseHeaders().get("Set-Cookie").stream().map(SetCookie::parse)
                            .filter(cookie -> !cookie.value().isEmpty())
                            .forEach(cookie -> cookies.put(cookie.name(), List.of(cookie.value())));
                    OidcAuthenticationRequestState state = OidcCookieStateHandler.create("default", tenant)
                            .decodeAuthenticationRequestState(cookies).orElseThrow();
                    assertThat(payload.stringValue("state"), is(Optional.of(state.state())));
                    assertThat(payload.stringValue("nonce"), is(Optional.of(state.nonce())));
                    assertThat(payload.stringValue("scope"), is(Optional.of("openid profile")));
                    if (par) {
                        assertThat(RECORDED_REQUEST.get().formParameters().keySet(), is(Set.of("request")));
                    }
                }
            }
        }
    }

    @Test
    void invalidTypedAuthorizationFailsBeforePushingOrIssuingCookies(URI serverUri) {
        for (Map.Entry<String, JsonValue> invalid : List.<Map.Entry<String, JsonValue>>of(
                Map.entry("max_age", JsonString.create("300")),
                Map.entry("max_age", JsonNumber.create(-1)),
                Map.entry("claims", JsonArray.create(List.of())),
                Map.entry("authorization_details", JsonArray.create(List.of(JsonObject.builder().build()))),
                Map.entry("iss", JsonString.create("other")))) {
            RECORDED_REQUEST.set(null);
            TYPED_JWK_REQUESTS.set(0);
            OidcTenantAdapter adapter = new OidcTenantAdapter() {
                @Override
                public String name() {
                    return "invalid-typed-test";
                }

                @Override
                public String type() {
                    return "invalid-typed-test";
                }

                @Override
                public OidcAuthorizationParameters authorizationRequest(OidcTenantConfig tenant,
                                                                        String tenantId,
                                                                        SecurityEnvironment environment,
                                                                        OidcAuthorizationParameters parameters) {
                    return OidcAuthorizationParameters.builder(parameters).addParameter(invalid.getKey(), invalid.getValue())
                            .buildPrototype();
                }
            };
            OidcTenantConfig tenant = typedAuthorizationTenant(serverUri, "JWE_PAR", adapter);
            try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder().putTenant("default", tenant)
                    .buildPrototype())) {
                AuthenticationResponse response = provider.authenticate(OidcProviderTest.request(null,
                        SecurityEnvironment.builder().targetUri(URI.create("https://rp.example/resource"))
                                .path("/resource").transport("https").build()));
                assertThat(response.statusCode().orElseThrow(), is(503));
                assertThat(response.responseHeaders(), not(hasKey("Location")));
                assertThat(response.responseHeaders().getOrDefault("Set-Cookie", List.of()), empty());
                assertThat(RECORDED_REQUEST.get(), nullValue());
                assertThat(TYPED_JWK_REQUESTS.get(), is(0));
            }
        }
    }

    @Test
    void parallelAuthorizationRequestsKeepTypedTemplatesAndBindingsIndependent(URI serverUri) throws Exception {
        List<JsonValue> templateValues = new ArrayList<>(List.of(JsonNumber.create(300)));
        OidcAuthorizationParameters template = OidcAuthorizationParameters.builder()
                .parameters(Map.of("max_age", templateValues)).buildPrototype();
        templateValues.set(0, JsonNumber.create(0));
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "parallel-typed-test";
            }

            @Override
            public String type() {
                return "parallel-typed-test";
            }

            @Override
            public OidcAuthorizationParameters authorizationRequest(OidcTenantConfig tenant,
                                                                    String tenantId,
                                                                    SecurityEnvironment environment,
                                                                    OidcAuthorizationParameters parameters) {
                return OidcAuthorizationParameters.builder(parameters).addParameters(template.parameters()).buildPrototype();
            }
        };
        OidcTenantConfig tenant = typedAuthorizationTenant(serverUri, "JAR", adapter);
        OidcProviderConfig config = OidcProviderConfig.builder().putTenant("default", tenant).buildPrototype();
        try (OidcProvider provider = OidcProvider.create(config);
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<AuthenticationResponse>> requests = new ArrayList<>();
            for (int index = 0; index < 12; index++) {
                requests.add(executor.submit(() -> provider.authenticate(OidcProviderTest.request(null,
                        SecurityEnvironment.builder().targetUri(URI.create("https://rp.example/resource"))
                                .path("/resource").transport("https").build()))));
            }
            Set<String> states = new HashSet<>();
            Set<String> nonces = new HashSet<>();
            Set<String> jwtIds = new HashSet<>();
            for (Future<AuthenticationResponse> request : requests) {
                AuthenticationResponse response = request.get(10, TimeUnit.SECONDS);
                assertThat(response.statusCode().orElseThrow(), is(303));
                JsonObject payload = typedRequestPayload(UriQuery.create(URI.create(response.responseHeaders().get("Location")
                        .getFirst())).get("request"));
                assertThat(payload.numberValue("max_age"), is(Optional.of(BigDecimal.valueOf(300))));
                states.add(payload.stringValue("state").orElseThrow());
                nonces.add(payload.stringValue("nonce").orElseThrow());
                jwtIds.add(payload.stringValue("jti").orElseThrow());
            }
            assertThat(states, hasSize(12));
            assertThat(nonces, hasSize(12));
            assertThat(jwtIds, hasSize(12));
        }
    }

    @Test
    void authorizationCodeFlowInitiationCanUseEncryptedRequestObject(URI serverUri) throws Exception {
        OidcTenantConfig tenant = encryptedRequestObjectTenant(serverUri, false, false, null);
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                            .putTenant("default", tenant)
                                                            .buildPrototype());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .path("/resource")
                .transport("https")
                .build();

        AuthenticationResponse response = provider.authenticate(OidcProviderTest.request(null, environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
        URI location = URI.create(response.responseHeaders().get("Location").getFirst());
        UriQuery query = UriQuery.create(location);
        assertThat(query.get("response_type"), is("code"));
        assertThat(query.get("client_id"), is(CLIENT_ID));
        assertThat(query.get("scope"), is("openid profile"));
        assertThat(query.contains("state"), is(false));
        assertThat(query.contains("nonce"), is(false));
        assertEncryptedRequestObject(query.get("request"), "A128CBC-HS256");
    }

    @Test
    void authorizationCodeFlowInitiationCanUseEncryptedRequestObjectWithPar(URI serverUri) throws Exception {
        responseStatus = 201;
        responseBody = validPushedAuthorizationResponse().toString();
        OidcTenantConfig tenant = encryptedRequestObjectTenant(serverUri, true, true, "A256GCM");
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                            .putTenant("default", tenant)
                                                            .buildPrototype());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .path("/resource")
                .transport("https")
                .build();

        AuthenticationResponse response = provider.authenticate(OidcProviderTest.request(null, environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
        URI location = URI.create(response.responseHeaders().get("Location").getFirst());
        UriQuery query = UriQuery.create(location);
        assertThat(query.get("client_id"), is(CLIENT_ID));
        assertThat(query.get("request_uri"), is(PUSHED_AUTHORIZATION_REQUEST_URI));
        assertThat(query.contains("request"), is(false));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.formParameters().keySet(), is(Set.of("request")));
        assertEncryptedRequestObject(request.formParameters().get("request").getFirst(), "A256GCM");
    }

    @Test
    void encryptedRequestObjectFailureDoesNotEscapeAuthenticationBoundary(URI serverUri) {
        JWK_SET.set(Resource.create("oidc-next-sign-public-jwk.json").string());
        OidcTenantConfig tenant = encryptedRequestObjectTenant(serverUri, false, false, null);
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                            .putTenant("default", tenant)
                                                            .buildPrototype());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .path("/resource")
                .transport("https")
                .build();

        AuthenticationResponse response = provider.authenticate(OidcProviderTest.request(null, environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(503));
        assertThat(response.description().orElse(""), is("OIDC authentication is unavailable"));
        assertThat(response.throwable().isEmpty(), is(true));
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
    void authorizationCodeExchangeSendsConfiguredResources() {
        OidcTokenEndpointResult result = exchange(confidentialTenantWithAuthorizationCodeResources(), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.formParameters().get("resource"),
                   is(List.of("https://api.example.com", "urn:example:contacts")));
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
    void refreshTokenGrantSendsConfiguredResources() {
        responseBody = validRefreshResponse().toString();

        OidcTokenEndpointResult result = refresh(confidentialTenantWithAuthorizationCodeResources(), REFRESH_TOKEN);

        assertThat(result.succeeded(), is(true));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.formParameters().get("resource"),
                   is(List.of("https://api.example.com", "urn:example:contacts")));
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

        String assertion = request.formParameters().get("client_assertion").getFirst();
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

        String assertion = request.formParameters().get("client_assertion").getFirst();
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
    void privateKeyJwtUsesConfiguredAlgorithmWhenJwkAlgIsOmitted() {
        OidcTokenEndpointResult result = exchange(privateKeyJwtTenant("RS384"), PKCE_VERIFIER);

        assertThat(result.succeeded(), is(true));
        SignedJwt assertion = SignedJwt.parseToken(
                RECORDED_REQUEST.get().formParameters().get("client_assertion").getFirst());
        assertThat(assertion.getJwt().algorithm().orElse(""), is("RS384"));
        assertThat(OidcJoseKeyPolicy.verifySignature(
                           assertion,
                           assertion.getJwt(),
                           signKeys).isValid(),
                   is(true));
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
    void privateKeyJwtRejectsPublicOnlyJwk() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantContext.ready("default", OidcTenantConfig.builder()
                                                               .issuer(ISSUER.toString())
                                                               .clientId(CLIENT_ID)
                                                               .tokenEndpointAuthenticationMethod(
                                                                       OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                                                               .clientAssertion(it -> it.jwk(ResourceConfig.builder()
                                                                       .resourcePath("oidc-next-sign-public-jwk.json")
                                                                       .buildPrototype())
                                                                       .algorithm("RS256")
                                                                       .keyId("sign-rsa"))
                                                               .endpoints(it -> it
                                                                       .authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                                                                       .tokenEndpointUri(tokenEndpointUri)
                                                                       .tlsRequired(false))
                                                               .authorizationCode(it -> it
                                                                       .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                                                               .cookies(it -> it.password("test-cookie-password"))
                                                               .buildPrototype()));

        assertThat(thrown.getMessage(), containsString("client-assertion.jwk"));
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

    private static void recordMutualTls(ServerRequest request) {
        MUTUAL_TLS_REQUESTS.incrementAndGet();
        MUTUAL_TLS_CERTIFICATE_PRESENT.set(request.remotePeer().tlsCertificates().isPresent());
    }

    private static OidcAuthenticationRequest authenticationRequest(OidcTenantConfig tenantConfig,
                                                                   SecurityEnvironment environment) {
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("default", tenantConfig)
                .buildPrototype();
        OidcTenantRuntimeRegistry tenantRuntimeRegistry = OidcTenantRuntimeRegistry.create(providerConfig);
        OidcRequestContext requestContext = new OidcRequestContext(OidcProviderTest.request(null, environment),
                                                                   tenantRuntimeRegistry);
        return new OidcAuthenticationRequestFactory().create(requestContext, List.of(), Optional.empty());
    }

    private static JsonObject typedRequestPayload(String compact) throws Exception {
        if (compact.split("\\.").length == 5) {
            JWEObject encrypted = JWEObject.parse(compact);
            encrypted.decrypt(new RSADecrypter((RSAPrivateKey) ((JwkRSA) encryptKeys.forKeyId("encrypt-rsa").orElseThrow())
                    .privateKey().orElseThrow()));
            compact = encrypted.getPayload().toString();
        }
        SignedJwt.parseToken(compact).verifySignature(signKeys).checkValid();
        return JsonParser.create(Base64.getUrlDecoder().decode(compact.split("\\.")[1])).readJsonObject();
    }

    private static WebClientConfig conventionalTlsWebClient() {
        return WebClientConfig.builder()
                .tls(tls -> tls.trust(trust -> trust
                        .keystore(store -> store
                                .passphrase("password")
                                .trustStore(true)
                                .keystore(Resource.create("client.p12")))))
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

    private static Tls serverTls(TlsClientAuth clientAuth) {
        Keys privateKeyConfig = serverKeys();
        return Tls.builder()
                .clientAuth(clientAuth)
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

    private static void assertEncryptedRequestObject(String requestObject,
                                                     String expectedContentEncryption) throws Exception {
        assertThat(requestObject.split("\\.", -1).length, is(5));
        EncryptedJwt encryptedJwt = EncryptedJwt.parseToken(requestObject);
        assertThat(encryptedJwt.headers().algorithm().orElse(""), is("RSA-OAEP-256"));
        assertThat(encryptedJwt.headers().encryption().orElse(""), is(expectedContentEncryption));
        assertThat(encryptedJwt.headers().contentType().orElse(""), is("JWT"));
        assertThat(encryptedJwt.headers().keyId().orElse(""), is("encrypt-rsa"));

        JwkRSA encryptionKey = (JwkRSA) encryptKeys.forKeyId("encrypt-rsa").orElseThrow();
        byte[] decryptedPayload = encryptedJwt.decryptPayload(encryptKeys, encryptionKey);
        String signedRequestObject = new String(decryptedPayload, StandardCharsets.UTF_8);
        String[] signedParts = signedRequestObject.split("\\.", -1);
        assertThat(signedParts.length, is(3));
        JsonObject signedHeader = JsonParser.create(Base64.getUrlDecoder().decode(signedParts[0])).readJsonObject();
        JsonObject signedClaims = JsonParser.create(Base64.getUrlDecoder().decode(signedParts[1])).readJsonObject();
        byte[] signedBytes = (signedParts[0] + "." + signedParts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] signature = Base64.getUrlDecoder().decode(signedParts[2]);
        assertThat(signKeys.forKeyId("sign-rsa").orElseThrow().verifySignature(signedBytes, signature), is(true));
        assertThat(signedHeader.stringValue("alg").orElse(""), is("RS256"));
        assertThat(signedHeader.stringValue("typ").orElse(""), is("JWT"));
        assertThat(signedHeader.stringValue("kid").orElse(""), is("sign-rsa"));
        assertThat(signedClaims.stringValue("iss").orElse(""), is(CLIENT_ID));
        assertThat(signedClaims.value("aud").orElseThrow()
                           .asArray()
                           .values()
                           .stream()
                           .map(value -> value.asString().value())
                           .toList(),
                   is(List.of(ISSUER.toString())));
        assertThat(signedClaims.stringValue("response_type").orElse(""), is("code"));
        assertThat(signedClaims.stringValue("client_id").orElse(""), is(CLIENT_ID));
        assertThat(signedClaims.containsKey("state"), is(true));
        assertThat(signedClaims.containsKey("nonce"), is(true));
        assertThat(signedClaims.containsKey("code_challenge"), is(true));
        assertThat(signedClaims.containsKey("request"), is(false));
        assertThat(signedClaims.containsKey("request_uri"), is(false));

        JWEObject nimbusJwe = JWEObject.parse(requestObject);
        nimbusJwe.decrypt(new RSADecrypter((RSAPrivateKey) encryptionKey.privateKey().orElseThrow()));
        SignedJWT nimbusSignedJwt = SignedJWT.parse(nimbusJwe.getPayload().toString());
        JwkRSA signingKey = (JwkRSA) signKeys.forKeyId("sign-rsa").orElseThrow();
        assertThat(nimbusSignedJwt.verify(new RSASSAVerifier((RSAPublicKey) signingKey.publicKey())), is(true));
        assertThat(nimbusSignedJwt.getJWTClaimsSet().getIssuer(), is(CLIENT_ID));
    }

    private static JsonObject validTokenResponse() {
        return validTokenResponse(_ -> { });
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

    private static JsonObject validPushedAuthorizationResponse() {
        return validPushedAuthorizationResponse(PUSHED_AUTHORIZATION_REQUEST_URI);
    }

    private static JsonObject validPushedAuthorizationResponse(String requestUri) {
        return JsonObject.builder()
                .set("request_uri", requestUri)
                .set("expires_in", 90)
                .build();
    }

    private static Parameters authorizationRequestParameters() {
        return Parameters.builder("test-authorization-request")
                .add("response_type", "code")
                .add("client_id", CLIENT_ID)
                .add("redirect_uri", REDIRECTION_ENDPOINT_URI.toString())
                .add("scope", "openid profile")
                .add("state", "state-value")
                .add("nonce", "nonce-value")
                .add("prompt", "login consent")
                .add("resource", "https://api.example.com")
                .add("resource", "urn:example:contacts")
                .add("code_challenge", "challenge-value")
                .add("code_challenge_method", "S256")
                .build();
    }

    private static Map<String, List<String>> formParameters(Parameters parameters) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (String name : parameters.names()) {
            result.put(name, parameters.all(name));
        }
        return result;
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

    private OidcPushedAuthorizationRequestResult pushedAuthorizationRequest(OidcTenantConfig tenantConfig,
                                                                            Parameters parameters) {
        return OidcTenantContext.ready("default", tenantConfig)
                .endpointClient()
                .pushedAuthorizationRequest(parameters);
    }

    private void assertPushedAuthorizationRequestWithReasonPhrase(String reasonPhrase) throws Exception {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
                SSLServerSocket listener = serverTls(TlsClientAuth.NONE).createServerSocket()) {
            // WebClient probes ALPN before sending HTTP; negotiate HTTP/1.1 so the probe carries the PAR request.
            SSLParameters tlsParameters = listener.getSSLParameters();
            tlsParameters.setApplicationProtocols(new String[] {"http/1.1"});
            listener.setSSLParameters(tlsParameters);
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 1);
            URI parUri = URI.create("https://localhost:" + listener.getLocalPort() + "/par");
            Future<?> served = executor.submit(() -> {
                try (SSLSocket socket = (SSLSocket) listener.accept()) {
                    socket.setSoTimeout(10_000);
                    socket.startHandshake();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(),
                                                                                      StandardCharsets.ISO_8859_1));
                    assertThat(reader.readLine(), is("POST /par HTTP/1.1"));
                    int contentLength = -1;
                    boolean chunked = false;
                    String lengthHeader = "Content-Length:";
                    String encodingHeader = "Transfer-Encoding:";
                    for (String line = reader.readLine(); line != null && !line.isEmpty(); line = reader.readLine()) {
                        if (line.regionMatches(true, 0, lengthHeader, 0, lengthHeader.length())) {
                            contentLength = Integer.parseInt(line.substring(lengthHeader.length()).strip());
                        } else if (line.regionMatches(true, 0, encodingHeader, 0, encodingHeader.length())) {
                            chunked = line.substring(encodingHeader.length()).strip().equalsIgnoreCase("chunked");
                        }
                    }
                    if (!chunked && contentLength < 0) {
                        throw new IllegalStateException("PAR test request is missing a body length");
                    }
                    char[] buffer = new char[1024];
                    int segmentLength = chunked ? Integer.parseInt(reader.readLine(), 16) : contentLength;
                    while (true) {
                        for (int remaining = segmentLength; remaining > 0;) {
                            int count = reader.read(buffer, 0, Math.min(buffer.length, remaining));
                            if (count < 0) {
                                throw new EOFException("Incomplete PAR test request body");
                            }
                            remaining -= count;
                        }
                        if (!chunked || segmentLength == 0) {
                            break;
                        }
                        assertThat(reader.readLine(), is(""));
                        segmentLength = Integer.parseInt(reader.readLine(), 16);
                    }
                    if (chunked) {
                        assertThat(reader.readLine(), is(""));
                    }
                    byte[] json = validPushedAuthorizationResponse().toString().getBytes(StandardCharsets.UTF_8);
                    String headers = "HTTP/1.1 201 " + reasonPhrase
                            + "\r\nContent-Type: application/json\r\nContent-Length: " + json.length
                            + "\r\nConnection: close\r\n\r\n";
                    socket.getOutputStream().write(headers.getBytes(StandardCharsets.US_ASCII));
                    socket.getOutputStream().write(json);
                    socket.getOutputStream().flush();
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
            OidcTenantConfig tenant = OidcTenantConfig.builder()
                    .issuer(ISSUER.toString())
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .webClient(WebClientConfig.builder(conventionalTlsWebClient())
                                       .socketOptions(SocketOptions.builder()
                                                              .readTimeout(Duration.ofSeconds(10))
                                                              .buildPrototype())
                                       .buildPrototype())
                    .endpoints(it -> it.pushedAuthorizationRequestEndpointUri(parUri).tlsRequired(false))
                    .buildPrototype();

            Future<OidcPushedAuthorizationRequestResult> sent = executor.submit(() ->
                    pushedAuthorizationRequest(tenant, authorizationRequestParameters()));
            served.get(10, TimeUnit.SECONDS);
            OidcPushedAuthorizationRequestResult result = sent.get(10, TimeUnit.SECONDS);
            assertThat(result.description() + ": " + result.cause(), result.succeeded(), is(true));
            assertThat(result.response().orElseThrow().requestUri(), is(PUSHED_AUTHORIZATION_REQUEST_URI));
            assertThat(result.response().orElseThrow().expiresIn(), is(90L));
        }
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

    private OidcTenantConfig typedAuthorizationTenant(URI serverUri, String mode, OidcTenantAdapter adapter) {
        return OidcTenantConfig.builder().issuer(ISSUER.toString()).clientId(CLIENT_ID).clientSecret(CLIENT_SECRET)
                .webClient(conventionalTlsWebClient()).adapter(adapter)
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(serverUri.resolve("authorize"))
                        .tokenEndpointUri(tokenEndpointUri).jwksUri(conventionalTlsServerUri.resolve("jwks"))
                        .pushedAuthorizationRequestEndpointUri(pushedAuthorizationRequestEndpointUri).tlsRequired(false))
                .authorizationCode(code -> {
                    code.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI).scopes(List.of("openid", "profile"))
                            .resources(List.of("https://api.example/one", "urn:example:two"))
                            .pushedAuthorizationRequests(mode.endsWith("PAR") ? OidcPushedAuthorizationRequestMode.REQUIRED
                                    : OidcPushedAuthorizationRequestMode.DISABLED);
                    if (mode.startsWith("JAR") || mode.startsWith("JWE")) {
                        code.requestObject(jar -> {
                            jar.mode(OidcRequestObjectMode.REQUIRED).signingKeyId("sign-rsa")
                                    .signingJwk(key -> key.resourcePath("oidc-next-sign-jwk.json"));
                            if (mode.startsWith("JWE")) {
                                jar.encryptionAlgorithm("RSA-OAEP-256").contentEncryptionAlgorithm("A256GCM")
                                        .encryptionKeyId("encrypt-rsa");
                            }
                        });
                    }
                }).cookies(cookies -> cookies.password("test-cookie-password"))
                .buildPrototype();
    }

    private OidcTenantConfig confidentialTenant() {
        return tenant(true, null);
    }

    private OidcTenantConfig confidentialParTenant() {
        return confidentialParTenant(null);
    }

    private OidcTenantConfig confidentialParTenant(OidcClientAuthenticationMethod method) {
        return parTenant(true, method);
    }

    private OidcTenantConfig confidentialTenantWithAuthorizationCodeResources() {
        return tenant(true, null, List.of("https://api.example.com", "urn:example:contacts"));
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

    private OidcTenantConfig outboundMutualTlsTenant(OidcClientAuthenticationMethod method, boolean outboundMutualTls) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .tokenEndpointAuthenticationMethod(method)
                .outboundMutualTls(outboundMutualTls)
                .webClient(mutualTlsWebClient())
                .update(builder -> {
                    if (method == OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC) {
                        builder.clientSecret(CLIENT_SECRET);
                    }
                    if (method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT) {
                        builder.clientAssertion(it -> it.jwk(ResourceConfig.builder()
                                .resourcePath("oidc-next-sign-jwk.json")
                                .buildPrototype())
                                .algorithm("RS256")
                                .keyId("sign-rsa"));
                    }
                })
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(conventionalTlsServerUri.resolve("token"))
                        .pushedAuthorizationRequestEndpointUri(conventionalTlsServerUri.resolve("par"))
                        .userInfoEndpointUri(conventionalTlsServerUri.resolve("userinfo")))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(_ -> { })
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
    }

    private OidcProviderMetadata providerMetadata(OidcTenantConfig tenant, boolean aliases) {
        JsonObject.Builder wellKnown = JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("token_endpoint", conventionalTlsServerUri.resolve("token").toString())
                .set("pushed_authorization_request_endpoint", conventionalTlsServerUri.resolve("par").toString())
                .set("userinfo_endpoint", conventionalTlsServerUri.resolve("userinfo").toString());
        if (aliases) {
            wellKnown.set("mtls_endpoint_aliases", JsonObject.builder()
                    .set("token_endpoint", mutualTlsServerUri.resolve("token").toString())
                    .set("pushed_authorization_request_endpoint", mutualTlsServerUri.resolve("par").toString())
                    .set("userinfo_endpoint", mutualTlsServerUri.resolve("userinfo").toString())
                    .build());
        }
        return OidcProviderMetadata.fromStaticConfig(tenant)
                .mergeWellKnownMetadata(OidcProviderMetadata.fromWellKnownMetadataJson(wellKnown.build()));
    }

    private OidcTenantConfig discoveredMutualTlsTenant(boolean userInfo, Optional<URI> wellKnownOverride) {
        OidcTenantConfig.Builder builder = OidcTenantConfig.builder()
                .issuer(conventionalIssuer())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .outboundMutualTls(true)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> {
                    wellKnownOverride.ifPresent(it::wellKnownUri);
                    it.authorizationEndpointUri(conventionalTlsServerUri.resolve("authorize"))
                            .tokenEndpointUri(conventionalTlsServerUri.resolve("token"));
                })
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.password("test-cookie-password"));
        if (userInfo) {
            builder.userInfo(_ -> { });
        }
        return builder.buildPrototype();
    }

    private JsonObject.Builder localWellKnownMetadata() {
        return JsonObject.builder()
                .set("issuer", conventionalIssuer())
                .set("authorization_endpoint", conventionalTlsServerUri.resolve("authorize").toString())
                .set("token_endpoint", conventionalTlsServerUri.resolve("token").toString())
                .set("jwks_uri", conventionalTlsServerUri.resolve("jwks").toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"));
    }

    private String conventionalIssuer() {
        String uri = conventionalTlsServerUri.toString();
        return uri.substring(0, uri.length() - 1);
    }

    private OidcTenantConfig privateKeyJwtTenant() {
        return privateKeyJwtTenant("RS256", "sign-rsa");
    }

    private OidcTenantConfig privateKeyJwtParTenant() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .webClient(conventionalTlsWebClient())
                .clientAssertion(it -> it.jwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-sign-jwk.json")
                        .buildPrototype())
                        .algorithm("RS256")
                        .keyId("sign-rsa"))
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(tokenEndpointUri)
                        .pushedAuthorizationRequestEndpointUri(pushedAuthorizationRequestEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
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
                    it.jwk(ResourceConfig.builder()
                            .resourcePath("oidc-next-sign-jwk.json")
                            .buildPrototype())
                            .algorithm(algorithm);
                    if (keyId != null) {
                        it.keyId(keyId);
                    }
                })
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
    }

    private OidcTenantConfig tenant(boolean clientSecret, OidcClientAuthenticationMethod method) {
        return tenant(clientSecret, method, List.of());
    }

    private OidcTenantConfig tenant(boolean clientSecret,
                                    OidcClientAuthenticationMethod method,
                                    List<String> authorizationCodeResources) {
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
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .resources(authorizationCodeResources))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
    }

    private OidcTenantConfig parTenant(boolean clientSecret, OidcClientAuthenticationMethod method) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .webClient(conventionalTlsWebClient())
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
                        .pushedAuthorizationRequestEndpointUri(pushedAuthorizationRequestEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
    }

    private OidcTenantConfig encryptedRequestObjectTenant(URI serverUri,
                                                           boolean pushedAuthorizationRequest,
                                                           boolean pinEncryptionKey,
                                                           String contentEncryptionAlgorithm) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .webClient(conventionalTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(serverUri.resolve("authorize"))
                        .tokenEndpointUri(tokenEndpointUri)
                        .jwksUri(serverUri.resolve("jwks"))
                        .pushedAuthorizationRequestEndpointUri(pushedAuthorizationRequestEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile"))
                        .prompts(List.of("login"))
                        .resources(List.of("https://api.example.com", "urn:example:contacts"))
                        .pushedAuthorizationRequests(pushedAuthorizationRequest
                                                             ? OidcPushedAuthorizationRequestMode.REQUIRED
                                                             : OidcPushedAuthorizationRequestMode.DISABLED)
                        .requestObject(requestObject -> {
                            requestObject.mode(OidcRequestObjectMode.REQUIRED)
                                    .signingJwk(jwk -> jwk.resourcePath("oidc-next-sign-jwk.json"))
                                    .signingKeyId("sign-rsa")
                                    .signingAlgorithm("RS256")
                                    .encryptionAlgorithm("RSA-OAEP-256");
                            if (pinEncryptionKey) {
                                requestObject.encryptionKeyId("encrypt-rsa");
                            }
                            if (contentEncryptionAlgorithm != null) {
                                requestObject.contentEncryptionAlgorithm(contentEncryptionAlgorithm);
                            }
                        }))
                .cookies(it -> it.password("test-cookie-password"))
                .buildPrototype();
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

    private record RecordedRequest(String method,
                                   String authorization,
                                   String contentType,
                                   List<String> cacheControl,
                                   Map<String, List<String>> formParameters) {
    }
}
