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
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.pki.Keys;
import io.helidon.common.tls.Tls;
import io.helidon.common.tls.TlsClientAuth;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.SecurityTime;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkOctet;
import io.helidon.security.providers.common.OutboundTarget;
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
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ServerTest
@Execution(ExecutionMode.SAME_THREAD)
class OidcClientCredentialsGrantTest {
    private static final String CLIENT_ID = "client/id";
    private static final String CLIENT_SECRET = "client+secret=value";
    private static final String EXISTING_HEADER_NAME = "X-Existing";
    private static final String EXISTING_HEADER_VALUE = "existing-value";
    private static final String TENANT_WEBCLIENT_HEADER = "X-Tenant-WebClient";
    private static final String TENANT_WEBCLIENT_HEADER_VALUE = "configured";
    private static final String CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final HeaderName TENANT_WEBCLIENT_HEADER_NAME = HeaderNames.create(TENANT_WEBCLIENT_HEADER);

    private static final AtomicInteger METADATA_REQUEST_COUNT = new AtomicInteger();
    private static final AtomicInteger REQUEST_COUNT = new AtomicInteger();
    private static final AtomicInteger REDIRECTED_REQUEST_COUNT = new AtomicInteger();
    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();
    private static volatile CountDownLatch tokenRequestStarted;
    private static volatile CountDownLatch releaseTokenResponse;

    private static volatile int responseStatus;
    private static volatile String responseBody;
    private static volatile String providerMetadata;
    private static volatile String redirectLocation;
    private static volatile boolean dynamicTokenResponse;
    private static volatile Integer dynamicExpiresIn;

    private static JwkKeys signKeys;

    private final URI mutualTlsServerUri;

    private URI issuer;
    private URI tokenEndpointUri;
    private URI secureTokenEndpointUri;
    private URI mutualTlsTokenEndpointUri;
    private URI redirectedTokenEndpointUri;

    OidcClientCredentialsGrantTest(WebServer server) {
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
        routing.get("/.well-known/openid-configuration", (request, response) -> {
            METADATA_REQUEST_COUNT.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(providerMetadata);
        });
        routing.post("/token", OidcClientCredentialsGrantTest::handleTokenEndpoint);
        routing.post("/mtls-token", OidcClientCredentialsGrantTest::handleTokenEndpoint);
        routing.post("/redirected-token", OidcClientCredentialsGrantTest::handleRedirectedTokenEndpoint);
    }

    @SetUpRoute("mtls")
    static void mutualTlsRouting(HttpRouting.Builder routing) {
        routing.get("/.well-known/openid-configuration", (request, response) -> {
            METADATA_REQUEST_COUNT.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(providerMetadata);
        });
        routing.post("/token", OidcClientCredentialsGrantTest::handleTokenEndpoint);
        routing.post("/mtls-token", OidcClientCredentialsGrantTest::handleTokenEndpoint);
    }

    @SetUpServer
    static void server(WebServerConfig.Builder builder) {
        builder.putSocket("mtls", socket -> socket.tls(serverTls()));
    }

    @BeforeEach
    void setUp(URI serverUri) {
        issuer = URI.create(serverUri.toString().substring(0, serverUri.toString().length() - 1));
        tokenEndpointUri = serverUri.resolve("token");
        secureTokenEndpointUri = mutualTlsServerUri.resolve("token");
        mutualTlsTokenEndpointUri = mutualTlsServerUri.resolve("mtls-token");
        redirectedTokenEndpointUri = serverUri.resolve("redirected-token");
        responseStatus = 200;
        responseBody = tokenResponse("access-token", 600).toString();
        providerMetadata = JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .setStrings("grant_types_supported", List.of("client_credentials"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                .build()
                .toString();
        redirectLocation = null;
        dynamicTokenResponse = false;
        dynamicExpiresIn = 600;
        METADATA_REQUEST_COUNT.set(0);
        REQUEST_COUNT.set(0);
        REDIRECTED_REQUEST_COUNT.set(0);
        RECORDED_REQUEST.set(null);
        tokenRequestStarted = null;
        releaseTokenResponse = null;
    }

    @Test
    void clientCredentialsGrantObtainsTokenAndUsesClientSecretBasic() {
        OidcProvider provider = provider(confidentialTenant(null, tenant -> tenant.webClient(tenantWebClient())));
        SecurityEnvironment outboundEnv = outboundEnvironment();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(), outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(response.requestHeaders().get(EXISTING_HEADER_NAME), is(List.of(EXISTING_HEADER_VALUE)));
        assertThat(REQUEST_COUNT.get(), is(1));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.method(), is("POST"));
        assertThat(request.authorization(),
                   is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
        assertThat(request.contentType(), is("application/x-www-form-urlencoded"));
        assertThat(request.tenantWebClientHeader(), is(TENANT_WEBCLIENT_HEADER_VALUE));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("client_credentials"))));
    }

    @Test
    void clientCredentialsGrantReplacesExistingAuthorizationHeaderCaseInsensitively() {
        OidcProvider provider = provider(confidentialTenant());
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("https://api.example.com/resource"))
                .transport("https")
                .path("/resource")
                .method("GET")
                .header("authorization", "Bearer stale-token")
                .build();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(response.requestHeaders().containsKey("authorization"), is(false));
    }

    @Test
    void clientCredentialsGrantCanUseClientSecretPost() {
        OidcProvider provider = provider(confidentialTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_POST));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("client_credentials"),
                                                       "client_id", List.of(CLIENT_ID),
                                                       "client_secret", List.of(CLIENT_SECRET))));
    }

    @Test
    void clientCredentialsGrantCanUseClientSecretJwt() {
        OidcProvider provider = provider(confidentialTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters().get("grant_type"), is(List.of("client_credentials")));
        assertThat(request.formParameters().get("client_assertion_type"), is(List.of(CLIENT_ASSERTION_TYPE)));
        assertThat(request.formParameters().containsKey("client_secret"), is(false));
        assertThat(request.formParameters().containsKey("client_id"), is(false));

        SignedJwt signedJwt = SignedJwt.parseToken(request.formParameters().get("client_assertion").getFirst());
        signedJwt.verifySignature(null, clientSecretJwk()).checkValid();
        assertClientAssertionClaims(signedJwt);
        assertThat(signedJwt.getJwt().algorithm().orElse(""), is("HS256"));
    }

    @Test
    void clientCredentialsGrantCanUsePrivateKeyJwt() {
        OidcProvider provider = provider(privateKeyJwtTenant());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters().get("grant_type"), is(List.of("client_credentials")));
        assertThat(request.formParameters().get("client_assertion_type"), is(List.of(CLIENT_ASSERTION_TYPE)));
        assertThat(request.formParameters().containsKey("client_secret"), is(false));
        assertThat(request.formParameters().containsKey("client_id"), is(false));

        SignedJwt signedJwt = SignedJwt.parseToken(request.formParameters().get("client_assertion").getFirst());
        signedJwt.verifySignature(signKeys).checkValid();
        assertClientAssertionClaims(signedJwt);
        assertThat(signedJwt.getJwt().algorithm().orElse(""), is("RS256"));
        assertThat(signedJwt.getJwt().keyId().orElse(""), is("sign-rsa"));
    }

    @Test
    void clientCredentialsGrantCanUseTlsClientAuth() {
        OidcProvider provider = provider(mutualTlsTenant(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("client_credentials"),
                                                       "client_id", List.of(CLIENT_ID))));
    }

    @Test
    void clientCredentialsGrantCanUseSelfSignedTlsClientAuth() {
        OidcProvider provider = provider(mutualTlsTenant(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("client_credentials"),
                                                       "client_id", List.of(CLIENT_ID))));
    }

    @Test
    void tlsClientAuthUsesWellKnownTokenEndpointAlias() {
        providerMetadata = JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", secureTokenEndpointUri.toString())
                .setStrings("grant_types_supported", List.of("client_credentials"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("tls_client_auth"))
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("token_endpoint", mutualTlsTokenEndpointUri.toString())
                        .build())
                .build()
                .toString();
        OidcProvider provider = provider(mutualTlsTenantFromWellKnown());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().path(), is("/mtls-token"));
    }

    @Test
    void selfSignedTlsClientAuthUsesWellKnownTokenEndpointAlias() {
        providerMetadata = JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", secureTokenEndpointUri.toString())
                .setStrings("grant_types_supported", List.of("client_credentials"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("self_signed_tls_client_auth"))
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("token_endpoint", mutualTlsTokenEndpointUri.toString())
                        .build())
                .build()
                .toString();
        OidcProvider provider = provider(mutualTlsTenantFromWellKnown(
                OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().path(), is("/mtls-token"));
    }

    @Test
    void mutualTlsClientCredentialsGrantUsesWellKnownTokenEndpointWhenAliasIsMissing() {
        providerMetadata = JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", secureTokenEndpointUri.toString())
                .setStrings("grant_types_supported", List.of("client_credentials"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("tls_client_auth"))
                .build()
                .toString();
        OidcProvider provider = provider(mutualTlsTenantFromWellKnown());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().path(), is("/token"));
    }

    @Test
    void explicitMutualTlsTokenEndpointOverridesWellKnownTokenEndpointAlias() {
        providerMetadata = JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code", "client_credentials"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("tls_client_auth"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .set("userinfo_endpoint", issuer.resolve("/userinfo").toString())
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("token_endpoint", mutualTlsTokenEndpointUri.toString())
                        .build())
                .build()
                .toString();
        OidcProvider provider = provider(mutualTlsTenantWithExplicitTokenEndpointAndUserInfo());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().path(), is("/token"));
    }

    @Test
    void nonMutualTlsClientCredentialsGrantIgnoresWellKnownTokenEndpointAlias() {
        providerMetadata = JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .setStrings("grant_types_supported", List.of("client_credentials"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("token_endpoint", mutualTlsTokenEndpointUri.toString())
                        .build())
                .build()
                .toString();
        OidcProvider provider = provider(confidentialTenantFromWellKnown());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().path(), is("/token"));
    }

    @Test
    void providerAndSupportCheckDeferMetadataUntilClientCredentialsRequest() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("default", confidentialTenantFromWellKnown())
                .buildPrototype());
        ProviderRequest providerRequest = providerRequest();
        SecurityEnvironment outboundEnvironment = outboundEnvironment();
        EndpointConfig endpointConfig = clientCredentialsEndpointConfig();

        assertThat(METADATA_REQUEST_COUNT.get(), is(0));
        assertThat(REQUEST_COUNT.get(), is(0));
        assertThat(provider.isOutboundSupported(providerRequest, outboundEnvironment, endpointConfig), is(true));
        assertThat(METADATA_REQUEST_COUNT.get(), is(0));
        assertThat(REQUEST_COUNT.get(), is(0));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest,
                                                                      outboundEnvironment,
                                                                      endpointConfig);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(METADATA_REQUEST_COUNT.get(), is(1));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetCanSelectClientCredentialsGrant() {
        OidcProvider provider = provider(confidentialTenant(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetClientCredentialsGrantCanRequestScope() {
        OidcProvider provider = provider(confidentialTenant(),
                                         scopedClientCredentialsTarget("orders.write", "orders.read"));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(REQUEST_COUNT.get(), is(1));
        assertThat(RECORDED_REQUEST.get().formParameters(),
                   is(Map.of("grant_type", List.of("client_credentials"),
                             "scope", List.of("orders.write orders.read"))));
    }

    @Test
    void outboundTargetClientCredentialsGrantCanRequestResources() {
        OidcProvider provider = provider(confidentialTenant(),
                                         resourceClientCredentialsTarget("https://orders.example.com",
                                                                         "api://inventory"));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(REQUEST_COUNT.get(), is(1));
        assertThat(RECORDED_REQUEST.get().formParameters(),
                   is(Map.of("grant_type", List.of("client_credentials"),
                             "resource", List.of("https://orders.example.com", "api://inventory"))));
    }

    @Test
    void outboundTargetClientCredentialsGrantCanRequestScopeAndResources() {
        OidcProvider provider = provider(confidentialTenant(),
                                         scopedResourceClientCredentialsTarget(List.of("orders.read"),
                                                                               List.of("https://orders.example.com")));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().formParameters(),
                   is(Map.of("grant_type", List.of("client_credentials"),
                             "scope", List.of("orders.read"),
                             "resource", List.of("https://orders.example.com"))));
    }

    @Test
    void scopedClientCredentialsGrantCanUseClientSecretPost() {
        OidcProvider provider = provider(confidentialTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_POST),
                                         scopedClientCredentialsTarget("orders.read"));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().formParameters(),
                   is(Map.of("grant_type", List.of("client_credentials"),
                             "scope", List.of("orders.read"),
                             "client_id", List.of(CLIENT_ID),
                             "client_secret", List.of(CLIENT_SECRET))));
    }

    @Test
    void scopedClientCredentialsGrantCanUsePrivateKeyJwt() {
        OidcProvider provider = provider(privateKeyJwtTenant(), scopedClientCredentialsTarget("orders.read"));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.formParameters().get("grant_type"), is(List.of("client_credentials")));
        assertThat(request.formParameters().get("scope"), is(List.of("orders.read")));
        assertThat(request.formParameters().get("client_assertion_type"), is(List.of(CLIENT_ASSERTION_TYPE)));
        assertThat(request.formParameters().containsKey("client_secret"), is(false));
        assertThat(request.formParameters().containsKey("client_id"), is(false));
    }

    @Test
    void outboundTargetClientCredentialsGrantMatchesHttpsUriWhenEnvironmentTransportIsStale() {
        OidcProvider provider = provider(confidentialTenant(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("https://api.example.com/resource"))
                .transport("http")
                .path("/resource")
                .method("GET")
                .build();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetClientCredentialsGrantMatchesUppercaseHttpsUriScheme() {
        OidcProvider provider = provider(confidentialTenant(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment("HTTPS://api.example.com/resource", "/resource");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyToOtherHost() {
        OidcProvider provider = provider(confidentialTenant(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://other.example.com/resource", "/resource");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyWhenTransportDiffersFromUriScheme() {
        OidcProvider provider = provider(confidentialTenant(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("http://api.example.com/resource"))
                .transport("https")
                .path("/resource")
                .method("GET")
                .build();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyToHttpWhenTlsIsRequired() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tokenEndpointUri(URI.create("https://issuer.example/token")))
                .buildPrototype();
        OidcProvider provider = provider(tenant, clientCredentialsTargetForAllTransports());
        SecurityEnvironment outboundEnv = outboundEnvironment("http://api.example.com/resource", "/resource");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void endpointClientCredentialsGrantDoesNotApplyToHttpWhenTlsIsRequired() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tokenEndpointUri(URI.create("https://issuer.example/token")))
                .buildPrototype();
        OidcProvider provider = provider(tenant);
        SecurityEnvironment outboundEnv = outboundEnvironment("http://api.example.com/resource", "/resource");
        EndpointConfig outboundConfig = clientCredentialsEndpointConfig();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      outboundConfig);

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, outboundConfig), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void endpointClientCredentialsGrantDoesNotApplyWhenTargetUriIsMissingAndTlsIsRequired() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tokenEndpointUri(URI.create("https://issuer.example/token")))
                .buildPrototype();
        OidcProvider provider = provider(tenant);
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .transport("https")
                .path("/resource")
                .method("GET")
                .build();
        EndpointConfig outboundConfig = clientCredentialsEndpointConfig();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      outboundConfig);

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, outboundConfig), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void endpointClientCredentialsGrantDoesNotApplyWhenTargetUriHasNoSchemeAndTlsIsRequired() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tokenEndpointUri(URI.create("https://issuer.example/token")))
                .buildPrototype();
        OidcProvider provider = provider(tenant);
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("/resource"))
                .transport("https")
                .path("/resource")
                .method("GET")
                .build();
        EndpointConfig outboundConfig = clientCredentialsEndpointConfig();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      outboundConfig);

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, outboundConfig), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void clientCredentialsGrantCanUseHttpOutboundTargetWhenTlsRequirementIsDisabled() {
        OidcProvider provider = provider(confidentialTenant(), clientCredentialsTargetForAllTransports());
        SecurityEnvironment outboundEnv = outboundEnvironment("http://api.example.com/resource", "/resource");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyToOtherPath() {
        OidcProvider provider = provider(confidentialTenant(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/other", "/other");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyToOtherMethod() {
        OidcProvider provider = provider(confidentialTenant(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/resource", "/resource", "POST");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void outboundTargetConfigCanSelectClientCredentialsGrant() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", CLIENT_ID),
                        Map.entry("tenants.default.client-secret", CLIENT_SECRET),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", tokenEndpointUri.toString()),
                        Map.entry("tenants.default.endpoints.tls-required", "false"),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/resource"),
                        Map.entry("outbound.0.methods.0", "GET"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));
        SecurityEnvironment outboundEnv = outboundEnvironment();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetConfigCanRequestClientCredentialsGrantScope() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", CLIENT_ID),
                        Map.entry("tenants.default.client-secret", CLIENT_SECRET),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", tokenEndpointUri.toString()),
                        Map.entry("tenants.default.endpoints.tls-required", "false"),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/resource"),
                        Map.entry("outbound.0.methods.0", "GET"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"),
                        Map.entry("outbound.0.client-credentials-scopes.0", "orders.write"),
                        Map.entry("outbound.0.client-credentials-scopes.1", "orders.read"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().formParameters(),
                   is(Map.of("grant_type", List.of("client_credentials"),
                             "scope", List.of("orders.write orders.read"))));
    }

    @Test
    void outboundTargetConfigCanRequestClientCredentialsGrantResources() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", CLIENT_ID),
                        Map.entry("tenants.default.client-secret", CLIENT_SECRET),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", tokenEndpointUri.toString()),
                        Map.entry("tenants.default.endpoints.tls-required", "false"),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/resource"),
                        Map.entry("outbound.0.methods.0", "GET"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"),
                        Map.entry("outbound.0.client-credentials-resources.0", "https://orders.example.com"),
                        Map.entry("outbound.0.client-credentials-resources.1", "api://inventory"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(RECORDED_REQUEST.get().formParameters(),
                   is(Map.of("grant_type", List.of("client_credentials"),
                             "resource", List.of("https://orders.example.com", "api://inventory"))));
    }

    @Test
    void outboundTargetConfigCanUseWellKnownMetadataTokenEndpoint() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.issuer", issuer.toString()),
                        Map.entry("tenants.default.client-id", CLIENT_ID),
                        Map.entry("tenants.default.client-secret", CLIENT_SECRET),
                        Map.entry("tenants.default.endpoints.tls-required", "false"),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/resource"),
                        Map.entry("outbound.0.methods.0", "GET"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void clientCredentialsGrantCacheSeparatesScopes() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = 600;
        OidcProvider provider = provider(confidentialTenant(),
                                         scopedClientCredentialsTarget("orders.read"),
                                         billingClientCredentialsTarget("billing.read"));

        OutboundSecurityResponse firstOrders = provider.outboundSecurity(providerRequest(),
                                                                         outboundEnvironment(),
                                                                         EndpointConfig.create());
        OutboundSecurityResponse billing = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment("https://api.example.com/billing",
                                                                                        "/billing"),
                                                                    EndpointConfig.create());
        OutboundSecurityResponse secondOrders = provider.outboundSecurity(providerRequest(),
                                                                          outboundEnvironment(),
                                                                          EndpointConfig.create());

        assertThat(firstOrders.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(billing.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-2")));
        assertThat(secondOrders.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void clientCredentialsGrantCacheSeparatesResources() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = 600;
        OidcProvider provider = provider(confidentialTenant(),
                                         scopedResourceClientCredentialsTarget(List.of("orders.read"),
                                                                               List.of("https://orders.example.com")),
                                         billingScopedResourceClientCredentialsTarget(List.of("orders.read"),
                                                                                      List.of("https://billing.example.com")));

        OutboundSecurityResponse firstOrders = provider.outboundSecurity(providerRequest(),
                                                                         outboundEnvironment(),
                                                                         EndpointConfig.create());
        OutboundSecurityResponse billing = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment("https://api.example.com/billing",
                                                                                        "/billing"),
                                                                    EndpointConfig.create());
        OutboundSecurityResponse secondOrders = provider.outboundSecurity(providerRequest(),
                                                                          outboundEnvironment(),
                                                                          EndpointConfig.create());

        assertThat(firstOrders.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(billing.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-2")));
        assertThat(secondOrders.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void clientCredentialsGrantCachesTokenUntilExpires() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = 600;
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(),
                                                                   outboundEnvironment(),
                                                                   EndpointConfig.create());
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment(),
                                                                    EndpointConfig.create());

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void concurrentClientCredentialsRequestsUseSingleTokenEndpointRequest() throws Exception {
        int taskCount = 32;
        dynamicTokenResponse = true;
        dynamicExpiresIn = 600;
        tokenRequestStarted = new CountDownLatch(1);
        releaseTokenResponse = new CountDownLatch(1);
        CountDownLatch start = new CountDownLatch(1);
        OidcProvider provider = provider(confidentialTenant());

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<OutboundSecurityResponse>> futures = new ArrayList<>(taskCount);
            for (int i = 0; i < taskCount; i++) {
                futures.add(executor.submit(() -> {
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    return provider.outboundSecurity(providerRequest(),
                                                     outboundEnvironment(),
                                                     EndpointConfig.create());
                }));
            }

            start.countDown();
            assertTrue(tokenRequestStarted.await(5, TimeUnit.SECONDS));
            releaseTokenResponse.countDown();
            for (Future<OutboundSecurityResponse> future : futures) {
                assertThat(future.get().requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                           is(List.of("Bearer access-token-1")));
            }
        } finally {
            releaseTokenResponse.countDown();
        }

        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void expiredClientCredentialsTokenIsReacquired() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = 120;
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(),
                                                                   outboundEnvironment(0),
                                                                   EndpointConfig.create());
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment(70),
                                                                    EndpointConfig.create());

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-2")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void clientCredentialsGrantDoesNotCacheTokenWithoutExpiresIn() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = null;
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(),
                                                                   outboundEnvironment(),
                                                                   EndpointConfig.create());
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment(),
                                                                    EndpointConfig.create());

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-2")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void clientCredentialsGrantDoesNotCacheTokenWithinClockSkew() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = 60;
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(),
                                                                   outboundEnvironment(),
                                                                   EndpointConfig.create());
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment(),
                                                                    EndpointConfig.create());

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-2")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void tokenEndpointErrorMapsToOutboundFailure() {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid_client")
                .set("error_description", "client authentication failed")
                .build()
                .toString();
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), is("Client Credentials Grant failed"));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void tokenEndpointRedirectIsNotFollowed() {
        responseStatus = 307;
        redirectLocation = redirectedTokenEndpointUri.toString();
        responseBody = JsonObject.builder()
                .set("error", "temporarily_unavailable")
                .build()
                .toString();
        OidcProvider provider = provider(confidentialTenant(
                OidcClientAuthenticationMethod.CLIENT_SECRET_POST,
                tenant -> tenant.webClient(redirectFollowingTenantWebClient())));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), is("Client Credentials Grant failed"));
        assertThat(REQUEST_COUNT.get(), is(1));
        assertThat(REDIRECTED_REQUEST_COUNT.get(), is(0));
        assertThat(RECORDED_REQUEST.get().tenantWebClientHeader(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void missingTokenEndpointMapsToOutboundFailure() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("default", OidcTenantConfig.builder()
                        .clientId(CLIENT_ID)
                        .clientSecret(CLIENT_SECRET)
                        .buildPrototype())
                .buildPrototype());
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.clientCredentialsGrant())
                .build();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      outboundConfig);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), is("Client Credentials Grant failed"));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void blankClientCredentialsGrantScopeIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> scopedTargetConfig("orders.read", " "));

        assertThat(thrown.getMessage(), containsString("client-credentials-scopes"));
    }

    @Test
    void paddedClientCredentialsGrantScopeIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> scopedTargetConfig(" orders.read"));

        assertThat(thrown.getMessage(), containsString("client-credentials-scopes"));
    }

    @Test
    void duplicateClientCredentialsGrantScopeIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> scopedTargetConfig("orders.read", "orders.read"));

        assertThat(thrown.getMessage(), containsString("duplicate scope"));
    }

    @Test
    void invalidClientCredentialsGrantScopeIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> scopedTargetConfig("orders\\read"));

        assertThat(thrown.getMessage(), containsString("invalid scope"));
    }

    @Test
    void clientCredentialsGrantScopeWithoutClientCredentialsGrantIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundTargetConfig.builder()
                                                               .addClientCredentialsScope("orders.read")
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-credentials-grant-enabled"));
    }

    @Test
    void blankClientCredentialsGrantResourceIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> resourceTargetConfig("https://orders.example.com", " "));

        assertThat(thrown.getMessage(), containsString("client-credentials-resources"));
    }

    @Test
    void paddedClientCredentialsGrantResourceIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> resourceTargetConfig(" https://orders.example.com"));

        assertThat(thrown.getMessage(), containsString("client-credentials-resources"));
    }

    @Test
    void duplicateClientCredentialsGrantResourceIsRejected() {
        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> resourceTargetConfig("https://orders.example.com", "https://orders.example.com"));

        assertThat(thrown.getMessage(), containsString("duplicate resource"));
    }

    @Test
    void relativeClientCredentialsGrantResourceIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> resourceTargetConfig("/orders"));

        assertThat(thrown.getMessage(), containsString("absolute resource URIs"));
    }

    @Test
    void fragmentedClientCredentialsGrantResourceIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> resourceTargetConfig("https://orders.example.com#read"));

        assertThat(thrown.getMessage(), containsString("must not contain URI fragments"));
    }

    @Test
    void clientCredentialsGrantResourceWithoutClientCredentialsGrantIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundTargetConfig.builder()
                                                               .addClientCredentialsResource("https://orders.example.com")
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-credentials-grant-enabled"));
    }

    private static void handleTokenEndpoint(ServerRequest request, ServerResponse response) {
        int requestNumber = REQUEST_COUNT.incrementAndGet();
        CountDownLatch requestStarted = tokenRequestStarted;
        if (requestStarted != null) {
            requestStarted.countDown();
        }
        CountDownLatch releaseResponse = releaseTokenResponse;
        if (releaseResponse != null) {
            await(releaseResponse);
        }
        RECORDED_REQUEST.set(new RecordedRequest(request.prologue().method().text(),
                                                request.requestedUri().path().path(),
                                                request.headers().first(HeaderNames.AUTHORIZATION).orElse(""),
                                                request.headers().first(HeaderNames.CONTENT_TYPE).orElse(""),
                                                request.headers().first(TENANT_WEBCLIENT_HEADER_NAME).orElse(""),
                                                formParameters(request.content().as(Parameters.class))));
        String body = dynamicTokenResponse
                ? tokenResponse("access-token-" + requestNumber, dynamicExpiresIn).toString()
                : responseBody;
        response.status(responseStatus)
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .header(HeaderNames.CACHE_CONTROL, "no-store")
                .header(HeaderNames.PRAGMA, "no-cache");
        if (redirectLocation != null) {
            response.header(HeaderNames.LOCATION, redirectLocation);
        }
        response.send(body);
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(5, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for Token Endpoint test response", e);
        }
    }

    private static void handleRedirectedTokenEndpoint(ServerRequest request, ServerResponse response) {
        REDIRECTED_REQUEST_COUNT.incrementAndGet();
        response.header(HeaderValues.CONTENT_TYPE_JSON)
                .header(HeaderNames.CACHE_CONTROL, "no-store")
                .header(HeaderNames.PRAGMA, "no-cache")
                .send(tokenResponse("redirected-access-token", 600));
    }

    private OidcTenantConfig confidentialTenant() {
        return confidentialTenant(null);
    }

    private OidcTenantConfig confidentialTenant(OidcClientAuthenticationMethod method) {
        return confidentialTenant(method, _ -> { });
    }

    private OidcTenantConfig confidentialTenant(OidcClientAuthenticationMethod method,
                                                Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig.Builder tenantBuilder = OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .update(builder -> {
                    if (method != null) {
                        builder.tokenEndpointAuthenticationMethod(method);
                    }
                })
                .endpoints(it -> it.tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false));
        tenantCustomizer.accept(tenantBuilder);
        return tenantBuilder.buildPrototype();
    }

    private OidcTenantConfig privateKeyJwtTenant() {
        return OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertion(it -> it.jwk(Resource.create("oidc-next-sign-jwk.json"))
                        .keyId("sign-rsa")
                        .algorithm("RS256"))
                .endpoints(it -> it.tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .buildPrototype();
    }

    private OidcTenantConfig mutualTlsTenant(OidcClientAuthenticationMethod method) {
        return OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .tokenEndpointAuthenticationMethod(method)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.tokenEndpointUri(secureTokenEndpointUri)
                        .tlsRequired(false))
                .buildPrototype();
    }

    private OidcTenantConfig mutualTlsTenantFromWellKnown() {
        return mutualTlsTenantFromWellKnown(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH);
    }

    private OidcTenantConfig mutualTlsTenantFromWellKnown(OidcClientAuthenticationMethod method) {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId(CLIENT_ID)
                .tokenEndpointAuthenticationMethod(method)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.wellKnownUri(mutualTlsServerUri.resolve(".well-known/openid-configuration"))
                        .tlsRequired(false))
                .buildPrototype();
    }

    private OidcTenantConfig mutualTlsTenantWithExplicitTokenEndpointAndUserInfo() {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId(CLIENT_ID)
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://issuer.example/authorize"))
                        .tokenEndpointUri(secureTokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(URI.create("https://rp.example/oidc/callback")))
                .userInfo(_ -> { })
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();
    }

    private OidcTenantConfig confidentialTenantFromWellKnown() {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
    }

    private static WebClientConfig tenantWebClient() {
        return WebClientConfig.builder()
                .addHeader(TENANT_WEBCLIENT_HEADER, TENANT_WEBCLIENT_HEADER_VALUE)
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

    private static WebClientConfig redirectFollowingTenantWebClient() {
        return WebClientConfig.builder()
                .addHeader(TENANT_WEBCLIENT_HEADER, TENANT_WEBCLIENT_HEADER_VALUE)
                .followRedirects(true)
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

    private static OutboundTarget clientCredentialsTarget() {
        return OutboundTarget.builder("api")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/resource")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget scopedClientCredentialsTarget(String... scopes) {
        return OutboundTarget.builder("api")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/resource")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class, scopedTargetConfig(scopes))
                .build();
    }

    private static OutboundTarget resourceClientCredentialsTarget(String... resources) {
        return OutboundTarget.builder("api")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/resource")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class, resourceTargetConfig(resources))
                .build();
    }

    private static OutboundTarget scopedResourceClientCredentialsTarget(List<String> scopes, List<String> resources) {
        return OutboundTarget.builder("api")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/resource")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class, scopedResourceTargetConfig(scopes, resources))
                .build();
    }

    private static OutboundTarget billingScopedResourceClientCredentialsTarget(List<String> scopes, List<String> resources) {
        return OutboundTarget.builder("billing")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/billing")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class, scopedResourceTargetConfig(scopes, resources))
                .build();
    }

    private static OutboundTarget billingClientCredentialsTarget(String... scopes) {
        return OutboundTarget.builder("billing")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/billing")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class, scopedTargetConfig(scopes))
                .build();
    }

    private static OidcOutboundTargetConfig scopedTargetConfig(String... scopes) {
        OidcOutboundTargetConfig.Builder builder = OidcOutboundTargetConfig.builder()
                .clientCredentialsGrantEnabled(true);
        for (String scope : scopes) {
            builder.addClientCredentialsScope(scope);
        }
        return builder.buildPrototype();
    }

    private static OidcOutboundTargetConfig resourceTargetConfig(String... resources) {
        OidcOutboundTargetConfig.Builder builder = OidcOutboundTargetConfig.builder()
                .clientCredentialsGrantEnabled(true);
        for (String resource : resources) {
            builder.addClientCredentialsResource(resource);
        }
        return builder.buildPrototype();
    }

    private static OidcOutboundTargetConfig scopedResourceTargetConfig(List<String> scopes, List<String> resources) {
        OidcOutboundTargetConfig.Builder builder = OidcOutboundTargetConfig.builder()
                .clientCredentialsGrantEnabled(true);
        scopes.forEach(builder::addClientCredentialsScope);
        resources.forEach(builder::addClientCredentialsResource);
        return builder.buildPrototype();
    }

    private static OutboundTarget clientCredentialsTargetForAllTransports() {
        return OutboundTarget.builder("api")
                .addHost("api.example.com")
                .addPath("/resource")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .buildPrototype())
                .build();
    }

    private static OidcProvider provider(OidcTenantConfig tenant, OutboundTarget... outboundTargets) {
        List<OutboundTarget> targets = outboundTargets.length == 0
                ? List.of(clientCredentialsTarget())
                : List.of(outboundTargets);
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .outboundTargets(targets)
                                           .buildPrototype());
    }

    private static EndpointConfig clientCredentialsEndpointConfig() {
        return EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.clientCredentialsGrant())
                .build();
    }

    private static ProviderRequest providerRequest() {
        return OidcProviderTest.request(null, SecurityEnvironment.create());
    }

    private static SecurityEnvironment outboundEnvironment() {
        return outboundEnvironment("https://api.example.com/resource", "/resource");
    }

    private static SecurityEnvironment outboundEnvironment(long timeShiftSeconds) {
        return outboundEnvironment("https://api.example.com/resource", "/resource", timeShiftSeconds);
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path) {
        return outboundEnvironment(targetUri, path, "GET");
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path, String method) {
        return outboundEnvironment(targetUri, path, method, 0);
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path, long timeShiftSeconds) {
        return outboundEnvironment(targetUri, path, "GET", timeShiftSeconds);
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri,
                                                          String path,
                                                          String method,
                                                          long timeShiftSeconds) {
        URI uri = URI.create(targetUri);
        return SecurityEnvironment.builder()
                .targetUri(uri)
                .transport(uri.getScheme())
                .path(path)
                .method(method)
                .header(EXISTING_HEADER_NAME, EXISTING_HEADER_VALUE)
                .time(SecurityTime.builder()
                              .shiftBySeconds(timeShiftSeconds)
                              .build())
                .build();
    }

    private static JsonObject tokenResponse(String accessToken, Integer expiresIn) {
        JsonObject.Builder builder = JsonObject.builder()
                .set("access_token", accessToken)
                .set("token_type", "Bearer");
        if (expiresIn != null) {
            builder.set("expires_in", expiresIn);
        }
        return builder.build();
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
                                   String path,
                                   String authorization,
                                   String contentType,
                                   String tenantWebClientHeader,
                                   Map<String, List<String>> formParameters) {
    }
}
