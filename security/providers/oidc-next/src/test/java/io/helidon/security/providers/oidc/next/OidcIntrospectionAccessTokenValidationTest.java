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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.pki.Keys;
import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.Grant;
import io.helidon.security.Role;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.SecurityTime;
import io.helidon.security.Subject;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static io.helidon.common.testing.junit5.MatcherWithRetry.assertThatWithRetry;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

@ServerTest
@Execution(ExecutionMode.SAME_THREAD)
class OidcIntrospectionAccessTokenValidationTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final String AUDIENCE = "api://default";
    private static final String SUBJECT = "user1-id";
    private static final String USERNAME = "user1";
    private static final String CLIENT_ID = "client/id";
    private static final String CLIENT_SECRET = "client+secret=value";
    private static final String OPAQUE_TOKEN = "opaque-token+value/=";
    private static final String TENANT_WEBCLIENT_HEADER = "X-Tenant-WebClient";
    private static final String TENANT_WEBCLIENT_HEADER_VALUE = "configured";
    private static final HeaderName TENANT_WEBCLIENT_HEADER_NAME = HeaderNames.create(TENANT_WEBCLIENT_HEADER);
    private static final String JWT_CLIENT_SECRET = "0123456789abcdef".repeat(4);
    private static final String INTROSPECTION_JWT_SECRET = "fedcba9876543210".repeat(4);
    private static final AtomicInteger DISCOVERY_REQUEST_COUNT = new AtomicInteger();

    private static int responseStatus;
    private static String responseBody;
    private static String responseContentType;
    private static volatile String discoveryResponseBody;
    private static String redirectLocation;
    private static final AtomicInteger REDIRECTED_REQUEST_COUNT = new AtomicInteger();
    private static final AtomicInteger REQUEST_COUNT = new AtomicInteger();
    private static final AtomicInteger ACTIVE_REQUESTS = new AtomicInteger();
    private static final AtomicInteger MAX_ACTIVE_REQUESTS = new AtomicInteger();
    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();
    private static volatile CountDownLatch introspectionRequestsStarted;
    private static volatile CountDownLatch releaseIntrospectionResponses;
    private static volatile Map<HeaderName, String> introspectionResponseHeaders = Map.of();

    private URI introspectionEndpointUri;
    private URI redirectedIntrospectionEndpointUri;
    private URI discoveryIssuer;

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.get("/.well-known/openid-configuration", (_, response) -> {
            DISCOVERY_REQUEST_COUNT.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON).send(discoveryResponseBody);
        });
        routing.post("/introspect", OidcIntrospectionAccessTokenValidationTest::handleIntrospection);
        routing.post("/redirected-introspect", (request, response) -> {
            REDIRECTED_REQUEST_COUNT.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(validResponse(_ -> { }));
        });
    }

    @BeforeEach
    void setUp(URI serverUri) {
        introspectionEndpointUri = serverUri.resolve("introspect");
        redirectedIntrospectionEndpointUri = serverUri.resolve("redirected-introspect");
        discoveryIssuer = URI.create(serverUri.getScheme() + "://" + serverUri.getRawAuthority());
        discoveryResponseBody = JsonObject.builder()
                .set("issuer", discoveryIssuer.toString())
                .set("token_endpoint", "https://issuer.example/token")
                .set("introspection_endpoint", introspectionEndpointUri.toString())
                .setStrings("token_endpoint_auth_methods_supported", List.of("private_key_jwt"))
                .setStrings("token_endpoint_auth_signing_alg_values_supported", List.of("RS256"))
                .setStrings("introspection_endpoint_auth_methods_supported", List.of("private_key_jwt"))
                .setStrings("introspection_endpoint_auth_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString();
        responseStatus = 200;
        responseBody = validResponse(_ -> { }).toString();
        responseContentType = "application/json";
        introspectionResponseHeaders = Map.of();
        redirectLocation = null;
        REDIRECTED_REQUEST_COUNT.set(0);
        REQUEST_COUNT.set(0);
        DISCOVERY_REQUEST_COUNT.set(0);
        ACTIVE_REQUESTS.set(0);
        MAX_ACTIVE_REQUESTS.set(0);
        RECORDED_REQUEST.set(null);
        introspectionRequestsStarted = null;
        releaseIntrospectionResponses = null;
    }

    @Test
    void validIntrospectionAuthenticatesSubject() {
        AuthenticationResponse response = authenticate(provider(tenant -> tenant.webClient(tenantWebClient())),
                                                       OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(), is(OidcTestIdentities.issuerSubject(ISSUER.toString(), SUBJECT)));
        assertThat(subject.principal().getName(), is(USERNAME));
        assertThat(subject.principal().abacAttributeRaw("email"), is("user1@example.org"));
        assertThat(subject.grants(Role.class).stream().map(Role::getName).toList(), is(List.of("admin", "auditor")));
        assertThat(subject.grantsByType("scope").stream().map(Grant::getName).toList(),
                   is(List.of("resource.read", "resource.write")));

        TokenCredential credential = subject.publicCredential(TokenCredential.class).orElseThrow();
        assertThat(credential.token(), is(OPAQUE_TOKEN));
        assertThat(credential.getIssuer().orElse(""), is(ISSUER.toString()));
        assertThat(credential.getIssueTime().isPresent(), is(true));
        assertThat(credential.getExpTime().isPresent(), is(true));
        assertThat(credential.getTokenInstance(JsonObject.class).isPresent(), is(true));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request, is(notNullValue()));
        assertThat(request.method(), is("POST"));
        assertThat(request.authorization(), is(basicAuthorization()));
        assertThat(request.contentType(), is("application/x-www-form-urlencoded"));
        assertThat(request.tenantWebClientHeader(), is(TENANT_WEBCLIENT_HEADER_VALUE));
        assertThat(request.formParameters(), is(Map.of("token", List.of(OPAQUE_TOKEN),
                                                       "token_type_hint", List.of("access_token"))));
        assertThat(response.responseHeaders().containsKey("Location"), is(false));
    }

    @Test
    void introspectionCanUseSeparateClientSecretPostAuthentication() {
        AuthenticationResponse response = authenticate(provider(tenant -> tenant
                .clientId("token-client")
                .clientSecret("token-secret")
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience(AUDIENCE)
                        .introspection(introspection -> introspection
                                .authenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_POST)
                                .clientId("introspection-client")
                                .clientSecret("introspection-secret"))))),
                                                       OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request, is(notNullValue()));
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("token", List.of(OPAQUE_TOKEN),
                                                       "token_type_hint", List.of("access_token"),
                                                       "client_id", List.of("introspection-client"),
                                                       "client_secret", List.of("introspection-secret"))));
    }

    @Test
    void mutualTlsIntrospectionPrefersDiscoveredAliasWithStaticConventionalEndpoint() {
        URI conventionalIntrospectionEndpointUri = URI.create("https://issuer.example/introspect");
        URI mutualTlsIntrospectionEndpointUri = URI.create("https://issuer.example/mtls-introspect");
        OidcTenantConfig mutualTlsTenant = introspectionTenant(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH,
                                                              conventionalIntrospectionEndpointUri);
        OidcProviderMetadata wellKnownMetadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("introspection_endpoint", "https://issuer.example/introspect")
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("introspection_endpoint", mutualTlsIntrospectionEndpointUri.toString())
                        .build())
                .build());
        OidcProviderMetadata metadata = OidcProviderMetadata.fromStaticConfig(mutualTlsTenant)
                .mergeWellKnownMetadata(wellKnownMetadata);

        assertThat(metadata.introspectionEndpointUri(), is(Optional.of(conventionalIntrospectionEndpointUri)));
        assertThat(metadata.mutualTlsIntrospectionEndpointUri(),
                   is(Optional.of(mutualTlsIntrospectionEndpointUri)));
        assertThat(OidcIntrospectionAccessTokenValidator.introspectionEndpointUri(
                           metadata,
                           OidcClientAuthenticationSupport.introspectionEndpoint(mutualTlsTenant)),
                   is(Optional.of(mutualTlsIntrospectionEndpointUri)));
        assertThat(OidcIntrospectionAccessTokenValidator.introspectionEndpointUri(
                           OidcProviderMetadata.fromStaticConfig(mutualTlsTenant),
                           OidcClientAuthenticationSupport.introspectionEndpoint(mutualTlsTenant)),
                   is(Optional.of(conventionalIntrospectionEndpointUri)));

        OidcTenantConfig conventionalTenant = OidcTenantConfig.builder()
                .from(introspectionTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                          conventionalIntrospectionEndpointUri))
                .outboundMutualTls(true)
                .buildPrototype();
        assertThat(OidcClientAuthenticationSupport.outboundMutualTls(conventionalTenant), is(true));
        assertThat(OidcIntrospectionAccessTokenValidator.introspectionEndpointUri(
                           metadata,
                           OidcClientAuthenticationSupport.introspectionEndpoint(conventionalTenant)),
                   is(Optional.of(conventionalIntrospectionEndpointUri)));
    }

    @Test
    void discoveredIntrospectionReusesInheritedPrivateKeyJwtMaterial() {
        responseBody = validResponse(builder -> builder.set("iss", discoveryIssuer.toString())).toString();
        OidcProvider provider = provider(tenant -> tenant
                .issuer(discoveryIssuer.toString())
                .clearClientSecret()
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertion(assertion -> assertion.jwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-sign-jwk.json")
                        .buildPrototype())
                        .keyId("sign-rsa")
                        .algorithm("RS256"))
                .endpoints(endpoints -> endpoints
                        .wellKnownUri(introspectionEndpointUri.resolve("/.well-known/openid-configuration"))
                        .tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience(AUDIENCE)
                        .introspection(introspection -> introspection
                                .authenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)))));
        JwkKeys keys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();

        AuthenticationResponse firstResponse = authenticate(provider, OPAQUE_TOKEN);
        assertThat(firstResponse.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest firstRequest = RECORDED_REQUEST.get();
        SignedJwt first = SignedJwt.parseToken(firstRequest.formParameters().get("client_assertion").getFirst());
        first.verifySignature(keys).checkValid();
        assertThat(first.getJwt().issuer().orElseThrow(), is(CLIENT_ID));
        assertThat(first.getJwt().subject().orElseThrow(), is(CLIENT_ID));
        assertThat(first.getJwt().audience().orElseThrow(), is(List.of(introspectionEndpointUri.toString())));
        assertThat(firstRequest.authorization(), is(""));
        assertThat(firstRequest.formParameters().containsKey("client_secret"), is(false));

        AuthenticationResponse secondResponse = authenticate(provider, OPAQUE_TOKEN);
        assertThat(secondResponse.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        SignedJwt second = SignedJwt.parseToken(RECORDED_REQUEST.get().formParameters().get("client_assertion").getFirst());
        second.verifySignature(keys).checkValid();
        assertThat(second.getJwt().jwtId(), not(first.getJwt().jwtId()));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void staticIntrospectionUsesInheritedSecretJwtAssertion() throws Exception {
        assertJwtIntrospection(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT, false, false);
    }

    @Test
    void staticIntrospectionUsesSeparateSecretJwtAssertion() throws Exception {
        assertJwtIntrospection(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT, false, true);
    }

    @Test
    void discoveredIntrospectionUsesInheritedSecretJwtAssertion() throws Exception {
        assertJwtIntrospection(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT, true, false);
    }

    @Test
    void discoveredIntrospectionUsesSeparateSecretJwtAssertion() throws Exception {
        assertJwtIntrospection(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT, true, true);
    }

    @Test
    void staticIntrospectionUsesInheritedPrivateKeyJwtAssertion() throws Exception {
        assertJwtIntrospection(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT, false, false);
    }

    @Test
    void staticIntrospectionUsesSeparatePrivateKeyJwtAssertion() throws Exception {
        assertJwtIntrospection(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT, false, true);
    }

    @Test
    void discoveredIntrospectionUsesInheritedPrivateKeyJwtAssertion() throws Exception {
        assertJwtIntrospection(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT, true, false);
    }

    @Test
    void discoveredIntrospectionUsesSeparatePrivateKeyJwtAssertion() throws Exception {
        assertJwtIntrospection(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT, true, true);
    }

    @Test
    void clientIdCanBeExplicitlySelectedWhenSubjectIsMissing() {
        responseBody = validResponse(it -> it.unset("sub")
                .unset("username")
                .unset("preferred_username")
                .set("client_id", "service-client")).toString();

        AuthenticationResponse response = authenticate(provider(tenant -> tenant
                .subjectMapping(mapping -> mapping.principalIdClaimPaths(List.of("client_id")))), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().id(),
                   is(OidcTestIdentities.issuerClaim(ISSUER.toString(), "client_id", "service-client")));
        assertThat(response.user().orElseThrow().principal().getName(), is("service-client"));
    }

    @Test
    void missingSubjectDoesNotSilentlySelectUsernameOrClientId() {
        responseBody = validResponse(it -> it.unset("sub")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Configured principal mapping cannot be satisfied");
    }

    @Test
    void explicitFallbackDoesNotMergeSubjectAndClientIdentities() {
        OidcProvider provider = provider(tenant -> tenant.subjectMapping(mapping -> mapping
                .principalIdClaimPaths(List.of("sub", "client_id"))));
        responseBody = validResponse(it -> it.set("sub", "123").set("client_id", "123")).toString();
        AuthenticationResponse subjectResponse = authenticate(provider, OPAQUE_TOKEN);

        responseBody = validResponse(it -> it.unset("sub").set("client_id", "123")).toString();
        AuthenticationResponse clientResponse = authenticate(provider, OPAQUE_TOKEN);

        assertThat(subjectResponse.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(clientResponse.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(clientResponse.user().orElseThrow().principal().id(),
                   not(subjectResponse.user().orElseThrow().principal().id()));
    }

    @Test
    void missingIssuerUsesTrustedTenantWithoutInventingAClaim() {
        responseBody = validResponse(it -> it.unset("iss")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(), is(OidcTestIdentities.issuerSubject(ISSUER.toString(), SUBJECT)));
        assertThat(subject.principal().abacAttributeNames().contains("iss"), is(false));
        TokenCredential credential = subject.publicCredential(TokenCredential.class).orElseThrow();
        assertThat(credential.getIssuer().isEmpty(), is(true));
        assertThat(credential.getTokenInstance(JsonObject.class).orElseThrow().value("iss").isEmpty(), is(true));
    }

    @Test
    void issuerlessIntrospectionUsesExplicitLocalNamespace() {
        responseBody = validResponse(it -> it.unset("iss")).toString();
        OidcProvider provider = provider(tenant -> tenant.clearIssuer()
                .subjectMapping(mapping -> mapping.principalIdNamespace("payments-authorization-server")));

        AuthenticationResponse response = authenticate(provider, OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().id(),
                   is(OidcTestIdentities.namespaceClaim("payments-authorization-server", "sub", SUBJECT)));
        assertThat(response.user().orElseThrow().principal().abacAttributeNames().contains("iss"), is(false));
    }

    @Test
    void introspectionResponseCannotChangeConfiguredLocalNamespace() {
        OidcProvider provider = provider(tenant -> tenant.clearIssuer()
                .subjectMapping(mapping -> mapping.principalIdNamespace("payments-authorization-server")));
        responseBody = validResponse(it -> it.unset("iss")).toString();
        AuthenticationResponse withoutIssuer = authenticate(provider, OPAQUE_TOKEN);

        responseBody = validResponse(it -> it.set("iss", "https://response-issuer.example")).toString();
        AuthenticationResponse withIssuer = authenticate(provider, OPAQUE_TOKEN);

        assertThat(withoutIssuer.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(withIssuer.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(withIssuer.user().orElseThrow().principal().id(),
                   is(withoutIssuer.user().orElseThrow().principal().id()));
    }

    @Test
    void localNamespaceCannotImpersonateIssuerQualifiedIdentity() {
        AuthenticationResponse issuerResponse = authenticate(provider(), OPAQUE_TOKEN);
        AuthenticationResponse namespaceResponse = authenticate(provider(tenant -> tenant.clearIssuer()
                .subjectMapping(mapping -> mapping.principalIdNamespace(ISSUER.toString()))), OPAQUE_TOKEN);

        assertThat(issuerResponse.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(namespaceResponse.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(namespaceResponse.user().orElseThrow().principal().id(),
                   not(issuerResponse.user().orElseThrow().principal().id()));
    }

    @Test
    void trustedIssuerTakesPrecedenceOverFallbackNamespace() {
        responseBody = validResponse(it -> it.unset("iss")).toString();
        AuthenticationResponse response = authenticate(provider(tenant -> tenant
                .subjectMapping(mapping -> mapping.principalIdNamespace("fallback"))), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().id(),
                   is(OidcTestIdentities.issuerSubject(ISSUER.toString(), SUBJECT)));
    }

    @Test
    void differentLocalNamespacesRemainDifferentIdentities() {
        responseBody = validResponse(it -> it.unset("iss")).toString();
        AuthenticationResponse first = authenticate(provider(tenant -> tenant.clearIssuer()
                .subjectMapping(mapping -> mapping.principalIdNamespace("first-authority"))), OPAQUE_TOKEN);
        AuthenticationResponse second = authenticate(provider(tenant -> tenant.clearIssuer()
                .subjectMapping(mapping -> mapping.principalIdNamespace("second-authority"))), OPAQUE_TOKEN);

        assertThat(first.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(second.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(second.user().orElseThrow().principal().id(), not(first.user().orElseThrow().principal().id()));
    }

    @Test
    void customMappingSupportsResponsesWithoutIssuerOrSubject() {
        responseBody = validResponse(it -> it.unset("iss").unset("sub")
                .unset("username").unset("preferred_username").set("client_id", "service-client")).toString();

        AuthenticationResponse response = authenticate(provider(tenant -> tenant.clearIssuer()
                .subjectMapping(mapping -> mapping.principalIdNamespace("service-authority")
                        .principalIdClaimPaths(List.of("client_id")))), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().id(),
                   is(OidcTestIdentities.namespaceClaim("service-authority", "client_id", "service-client")));
        assertThat(response.user().orElseThrow().principal().getName(), is("service-client"));
    }

    @Test
    void missingDisplayNameFallsBackToRawSubject() {
        responseBody = validResponse(it -> it.unset("username").unset("preferred_username")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().getName(), is(SUBJECT));
        assertThat(response.user().orElseThrow().principal().id(), not(SUBJECT));
    }

    @Test
    void unpairedSurrogateInPrincipalClaimIsRejected() {
        responseBody = validResponse(_ -> { }).toString().replace("\"" + SUBJECT + "\"", "\"\\uD800\"");

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        // The JSON parser rejects the unpaired surrogate before identity mapping can run.
        assertIntrospectionUnavailable(response);
    }

    @Test
    void customSubjectMappingAppliesToIntrospection() {
        responseBody = validResponse(it -> it
                .set("principal_id", "opaque-user-id")
                .set("display_name", "Opaque User")
                .set("realm_access", realm -> realm.setStrings("roles", List.of("realm-admin", "realm-auditor")))
                .setStrings("scp", List.of("resource.audit", "resource.export"))).toString();

        AuthenticationResponse response = authenticate(provider(tenant -> tenant
                .subjectMapping(mapping -> mapping
                        .principalIdClaimPaths(List.of("principal_id"))
                        .principalNameClaimPaths(List.of("display_name"))
                        .roleClaimPaths(List.of("realm_access.roles"))
                        .scopeClaimPaths(List.of("scp")))), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(),
                   is(OidcTestIdentities.issuerClaim(ISSUER.toString(), "principal_id", "opaque-user-id")));
        assertThat(subject.principal().getName(), is("Opaque User"));
        assertThat(subject.grants(Role.class).stream().map(Role::getName).toList(),
                   is(List.of("realm-admin", "realm-auditor")));
        assertThat(subject.grantsByType("scope").stream().map(Grant::getName).toList(),
                   is(List.of("resource.audit", "resource.export")));
    }

    @Test
    void standardScopeClaimMustBeStringForIntrospection() {
        responseBody = validResponse(it -> it.setStrings("scope", List.of("resource.read"))).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void standardScopeClaimRejectsNonSpaceDelimiterForIntrospection() {
        responseBody = validResponse(it -> it.set("scope", "resource.read\tresource.write")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void customScopeArrayValuesMustBeScopeTokensForIntrospection() {
        responseBody = validResponse(it -> it.setStrings("scp", List.of("resource.audit resource.export")))
                .toString();

        AuthenticationResponse response = authenticate(provider(tenant -> tenant
                .subjectMapping(mapping -> mapping.scopeClaimPaths(List.of("scp")))), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void customPrincipalIdClaimIsRequiredForIntrospection() {
        AuthenticationResponse response = authenticate(provider(tenant -> tenant
                .subjectMapping(mapping -> mapping.principalIdClaimPaths(List.of("principal_id")))), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response has no principal claim");
    }

    @Test
    void principalIdClaimMustBeScalarForIntrospection() {
        responseBody = validResponse(it -> it.setStrings("principal_id", List.of("first-user", "second-user")))
                .toString();

        AuthenticationResponse response = authenticate(provider(tenant -> tenant
                .subjectMapping(mapping -> mapping.principalIdClaimPaths(List.of("principal_id")))), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response has no principal claim");
    }

    @Test
    void scopeGrantsCanBeDisabledForIntrospection() {
        responseBody = validResponse(it -> it.setStrings("scp", List.of("resource.audit", "resource.export")))
                .toString();

        AuthenticationResponse response = authenticate(provider(tenant -> tenant
                .subjectMapping(mapping -> mapping
                        .scopeClaimPaths(List.of("scope", "scp"))
                        .scopeGrantsEnabled(false))), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().grantsByType("scope").isEmpty(), is(true));
    }

    @Test
    void bearerEvidenceWinsOverAuthorizationCodeFlowForIntrospection() {
        AuthenticationResponse response = provider().authenticate(
                OidcProviderTest.request(OidcEndpointPolicy.protectedResourceAndAuthorizationCodeFlow(),
                                         SecurityEnvironment.builder()
                                                 .targetUri(URI.create("https://rp.example/resource"))
                                                 .header("Authorization", "Bearer " + OPAQUE_TOKEN)
                                                 .build()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.responseHeaders().containsKey("Location"), is(false));
    }

    @Test
    void inactiveIntrospectionResponseIsRejected() {
        responseBody = JsonObject.builder()
                .set("active", false)
                .build()
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response is inactive");
    }

    @Test
    void missingActiveIntrospectionResponseIsRejected() {
        responseBody = validResponse(it -> it.unset("active")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertIntrospectionUnavailable(response);
    }

    @Test
    void wrongIssuerIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("iss", "https://other.example")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void wrongAudienceIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.setStrings("aud", List.of("api://other"))).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void missingAudienceIsRejectedWhenAudienceValidationIsEnabled() {
        responseBody = validResponse(it -> it.unset("aud")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void audienceValidationCanBeDisabled() {
        responseBody = validResponse(it -> it.setStrings("aud", List.of("api://other"))).toString();

        AuthenticationResponse response = authenticate(provider(false), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void audienceValidationCanBeDisabledWithoutConfiguredAudience() {
        responseBody = validResponse(it -> it.setStrings("aud", List.of("api://other"))).toString();

        AuthenticationResponse response = authenticate(provider(false, false), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void expiredTokenIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("exp", Instant.now().minus(5, ChronoUnit.MINUTES).getEpochSecond()))
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void futureNotBeforeIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("nbf", Instant.now().plus(5, ChronoUnit.MINUTES).getEpochSecond()))
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void requestSecurityTimeDeterminesTokenTimeValidation() {
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .header("Authorization", "Bearer " + OPAQUE_TOKEN)
                .time(SecurityTime.builder().shiftBySeconds(Duration.ofHours(2).toSeconds()).build())
                .build();

        AuthenticationResponse response = provider().authenticate(OidcProviderTest.request(null, environment));

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void fractionalNumericDateIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("exp", 1_773_000_000.5)).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertIntrospectionUnavailable(response);
    }

    @Test
    void stringNumericDateIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("nbf", "1773000000")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertIntrospectionUnavailable(response);
    }

    @Test
    void outOfRangeNumericDateIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("iat", BigDecimal.valueOf(Long.MAX_VALUE)
                .add(BigDecimal.ONE))).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertIntrospectionUnavailable(response);
    }

    @Test
    void dpopBoundIntrospectionResponseIsRejectedAsBearer() {
        responseBody = validResponse(it -> it.set("cnf", cnf -> cnf.set("jkt", "dpop-key-thumbprint")))
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void dpopBoundIntrospectionResponseIsRejectedEvenWithMatchingCertificateBoundClaim() {
        Certificate certificate = OidcTestCertificates.certificate("client-certificate");
        responseBody = validResponse(it -> it.set("cnf", cnf -> cnf
                .set("jkt", "dpop-key-thumbprint")
                .set("x5t#S256", OidcTestCertificates.thumbprint(certificate))))
                .toString();

        AuthenticationResponse response = authenticate(provider(OidcCertificateBoundAccessTokenMode.IF_PRESENT),
                                                       OPAQUE_TOKEN,
                                                       certificate);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void certificateBoundIntrospectionResponseIsRejectedAsBearer() {
        responseBody = validResponse(it -> it.set("cnf", cnf -> cnf.set("x5t#S256", "certificate-thumbprint")))
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void certificateBoundIntrospectionResponseAuthenticatesWithMatchingPeerCertificate() {
        Certificate certificate = OidcTestCertificates.certificate("client-certificate");
        responseBody = validResponse(it -> it.set("cnf", cnf -> cnf
                .set("x5t#S256", OidcTestCertificates.thumbprint(certificate))))
                .toString();

        AuthenticationResponse response = authenticate(provider(OidcCertificateBoundAccessTokenMode.IF_PRESENT),
                                                       OPAQUE_TOKEN,
                                                       certificate);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void certificateBoundIntrospectionResponseAuthenticatesWhenRequiredWithMatchingPeerCertificate() {
        Certificate certificate = OidcTestCertificates.certificate("client-certificate");
        responseBody = validResponse(it -> it.set("cnf", cnf -> cnf
                .set("x5t#S256", OidcTestCertificates.thumbprint(certificate))))
                .toString();

        AuthenticationResponse response = authenticate(provider(OidcCertificateBoundAccessTokenMode.REQUIRED),
                                                       OPAQUE_TOKEN,
                                                       certificate);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void certificateBoundIntrospectionResponseRequiresPeerCertificate() {
        Certificate certificate = OidcTestCertificates.certificate("client-certificate");
        responseBody = validResponse(it -> it.set("cnf", cnf -> cnf
                .set("x5t#S256", OidcTestCertificates.thumbprint(certificate))))
                .toString();

        AuthenticationResponse response = authenticate(provider(OidcCertificateBoundAccessTokenMode.IF_PRESENT),
                                                       OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void certificateBoundIntrospectionResponseRejectsMismatchedPeerCertificate() {
        Certificate tokenCertificate = OidcTestCertificates.certificate("token-certificate");
        Certificate requestCertificate = OidcTestCertificates.certificate("request-certificate");
        responseBody = validResponse(it -> it.set("cnf", cnf -> cnf
                .set("x5t#S256", OidcTestCertificates.thumbprint(tokenCertificate))))
                .toString();

        AuthenticationResponse response = authenticate(provider(OidcCertificateBoundAccessTokenMode.IF_PRESENT),
                                                       OPAQUE_TOKEN,
                                                       requestCertificate);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void certificateBoundIntrospectionResponseRejectsMalformedThumbprint() {
        responseBody = validResponse(it -> it.set("cnf", cnf -> cnf
                .set("x5t#S256", "not-a-sha256-thumbprint")))
                .toString();

        AuthenticationResponse response = authenticate(provider(OidcCertificateBoundAccessTokenMode.IF_PRESENT),
                                                       OPAQUE_TOKEN,
                                                       OidcTestCertificates.certificate("client-certificate"));

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void unboundIntrospectionResponseAuthenticatesWhenCertificateBindingIsIfPresent() {
        AuthenticationResponse response = authenticate(provider(OidcCertificateBoundAccessTokenMode.IF_PRESENT),
                                                       OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void unboundIntrospectionResponseIsRejectedWhenCertificateBindingIsRequired() {
        AuthenticationResponse response = authenticate(provider(OidcCertificateBoundAccessTokenMode.REQUIRED),
                                                       OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void missingPrincipalClaimIsRejected() {
        responseBody = validResponse(it -> it.unset("sub")
                .unset("username")
                .unset("preferred_username")
                .unset("client_id")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response has no principal claim");
    }

    @Test
    void unsupportedTokenTypeIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("token_type", "mac")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void dpopTokenTypeIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("token_type", "DPoP")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void malformedIntrospectionResponseIsRejected() {
        responseBody = "{not-json";

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertIntrospectionUnavailable(response);
    }

    @Test
    void introspectionResponseWithoutJsonContentTypeIsRejected() {
        responseContentType = "text/plain";

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertIntrospectionUnavailable(response);
    }

    @Test
    void nonSuccessfulIntrospectionResponseIsRejected() {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid_request")
                .build()
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertIntrospectionUnavailable(response);
    }

    @Test
    void unavailableIntrospectionEndpointIsRejected() {
        responseStatus = 503;
        responseBody = JsonObject.builder()
                .set("error", "temporarily_unavailable")
                .build()
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertIntrospectionUnavailable(response);
    }

    @Test
    void upstreamErrorsDoNotRejectTheTokenOrLeakHeadersAndRecoveryReusesThePermit() {
        OidcProvider provider = limitedIntrospectionProvider(Duration.ofSeconds(5));
        int requests = 0;
        for (int status : List.of(301, 302, 307, 308, 400, 401, 403, 404, 405, 408, 415, 422, 429, 500, 502, 503, 504)) {
            responseStatus = status;
            responseBody = JsonObject.builder()
                    .set("active", false)
                    .set("error", "invalid_token")
                    .set("error_description", "upstream-private-data:" + OPAQUE_TOKEN + CLIENT_SECRET)
                    .build().toString();
            introspectionResponseHeaders = Map.of(HeaderNames.WWW_AUTHENTICATE, "Basic realm=\"upstream-private\"",
                                                  HeaderNames.SET_COOKIE, "upstream-session=private",
                                                  HeaderNames.LOCATION, redirectedIntrospectionEndpointUri.toString(),
                                                  HeaderNames.RETRY_AFTER, "86400");

            AuthenticationResponse rejected = authenticate(provider, OPAQUE_TOKEN);

            assertIntrospectionUnavailable(rejected);
            assertThat("one introspection request for upstream HTTP " + status, REQUEST_COUNT.get(), is(++requests));
            assertThat(REDIRECTED_REQUEST_COUNT.get(), is(0));
            responseStatus = 200;
            responseBody = validResponse(_ -> { }).toString();
            introspectionResponseHeaders = Map.of();

            AuthenticationResponse recovered = authenticate(provider, OPAQUE_TOKEN);

            assertThat(recovered.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(REQUEST_COUNT.get(), is(++requests));
        }
    }

    @Test
    void unusableIntrospectionResponsesDoNotEstablishTokenInvalidity() {
        OidcProvider provider = provider();
        for (String body : List.of("", "null", "[]", "{}", "{not-json", "{\"active\":null}",
                                   "{\"active\":\"false\"}", "{\"active\":1}", "{\"active\":[]}")) {
            responseBody = body;
            assertIntrospectionUnavailable(authenticate(provider, OPAQUE_TOKEN));
        }
        responseBody = JsonObject.builder().set("active", false).set("exp", "ignored-for-inactive-token").build().toString();

        assertInvalidToken(authenticate(provider, OPAQUE_TOKEN), "Inactive token remains a token rejection");
    }

    @Test
    void introspectionReadTimeoutReturnsUnavailableAndReleasesPermit() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        introspectionRequestsStarted = started;
        releaseIntrospectionResponses = release;
        OidcProvider provider = limitedIntrospectionProvider(Duration.ofMillis(500));
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            try {
                Future<AuthenticationResponse> outcome = executor.submit(() -> {
                    AuthenticationResponse response = authenticate(provider, OPAQUE_TOKEN);
                    assertThat(Thread.currentThread().isInterrupted(), is(false));
                    return response;
                });
                assertThat(started.await(5, TimeUnit.SECONDS), is(true));
                assertIntrospectionUnavailable(outcome.get(5, TimeUnit.SECONDS));
                releaseIntrospectionResponses = null;

                assertThat(authenticate(provider, OPAQUE_TOKEN).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                assertThat(REQUEST_COUNT.get(), is(2));
            } finally {
                release.countDown();
                assertThatWithRetry(ACTIVE_REQUESTS::get, is(0));
            }
        }
    }

    @RepeatedTest(10)
    void interruptedVirtualThreadReturnsUnavailableAndReleasesPermit() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        introspectionRequestsStarted = started;
        releaseIntrospectionResponses = release;
        OidcProvider provider = limitedIntrospectionProvider(Duration.ofSeconds(10));
        CompletableFuture<AuthenticationResponse> outcome = new CompletableFuture<>();
        AtomicBoolean interruptPreserved = new AtomicBoolean();
        Thread worker = Thread.ofVirtual().start(() -> {
            try {
                AuthenticationResponse response = authenticate(provider, OPAQUE_TOKEN);
                interruptPreserved.set(Thread.currentThread().isInterrupted());
                outcome.complete(response);
            } catch (Throwable t) {
                outcome.completeExceptionally(t);
            }
        });
        try {
            assertThat(started.await(5, TimeUnit.SECONDS), is(true));
            worker.interrupt();
            assertIntrospectionUnavailable(outcome.get(5, TimeUnit.SECONDS));
            assertThat(interruptPreserved.get(), is(true));
            releaseIntrospectionResponses = null;

            assertThat(authenticate(provider, OPAQUE_TOKEN).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(REQUEST_COUNT.get(), is(2));
        } finally {
            release.countDown();
            worker.interrupt();
            worker.join(5_000);
            assertThatWithRetry(ACTIVE_REQUESTS::get, is(0));
        }
        assertThat(worker.isAlive(), is(false));
    }

    @Test
    void introspectionConnectionFailureDoesNotRejectTheToken() {
        WebServer stopped = WebServer.builder().port(0).build().start();
        URI endpoint = URI.create("http://localhost:" + stopped.port() + "/introspect");
        stopped.stop();
        OidcProvider provider = provider(tenant -> tenant
                .endpoints(endpoints -> endpoints.introspectionEndpointUri(endpoint).tlsRequired(false))
                .webClient(WebClientConfig.builder().connectTimeout(Duration.ofSeconds(1)).buildPrototype()));

        assertIntrospectionUnavailable(authenticate(provider, OPAQUE_TOKEN));
    }

    @Test
    void unavailableIntrospectionRetainsInternalCauseAndHttpStatusDiagnostics() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString()).clientId(CLIENT_ID).clientSecret(CLIENT_SECRET)
                .endpoints(endpoints -> endpoints.introspectionEndpointUri(introspectionEndpointUri).tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION).audience(AUDIENCE)))
                .buildPrototype();
        OidcTenantContext context = OidcTenantContextFactory.create(false, false).create("default", tenant);
        try {
            assertThat(context.ready(), is(true));
            responseBody = "{not-json";
            OidcIntrospectionAccessTokenValidator validator = new OidcIntrospectionAccessTokenValidator();
            OidcAccessTokenValidationRequest request = OidcAccessTokenValidationRequest
                    .refreshedAuthorizationCodeAccessToken(OPAQUE_TOKEN, context, Instant.now());
            OidcValidationResult<OidcValidatedAccessToken> malformed = validator.validate(request);

            assertThat(malformed.unavailable(), is(true));
            assertThat(malformed.succeeded(), is(false));
            assertThat(malformed.validatedToken().isEmpty(), is(true));
            assertThat(malformed.cause().isPresent(), is(true));
            assertThat(malformed.errorDescription().orElseThrow(), is("Bearer Token introspection response is invalid"));
            responseStatus = 401;
            OidcValidationResult<OidcValidatedAccessToken> rejected = validator.validate(request);

            assertThat(rejected.unavailable(), is(true));
            assertThat(rejected.cause().isEmpty(), is(true));
            assertThat(rejected.errorDescription().orElseThrow(), is("Bearer Token introspection endpoint returned HTTP 401"));
        } finally {
            if (context.ready()) {
                context.webClient().closeResource();
            }
        }
    }

    @Test
    void highCardinalityIntrospectionFloodIsBoundedAndRecovers() throws Exception {
        int taskCount = 1_000;
        int maxConcurrent = 4;
        int maxQueued = 8;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch overloadObserved = new CountDownLatch(1);
        introspectionRequestsStarted = new CountDownLatch(maxConcurrent);
        releaseIntrospectionResponses = new CountDownLatch(1);
        // This cohort must reach introspection admission rather than be rejected during tenant initialization.
        OidcProvider provider = provider(tenant -> tenant.initializationMaxQueued(taskCount).protectedResource(resource -> resource
                .tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience(AUDIENCE)
                        .introspection(introspection -> introspection.remoteWork(remoteWork -> remoteWork
                                .maxConcurrent(maxConcurrent)
                                .maxQueued(maxQueued)
                                .admissionTimeout(Duration.ofMillis(100)))))));

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<AuthenticationResponse>> futures = new ArrayList<>(taskCount);
            for (int i = 0; i < taskCount; i++) {
                String token = "opaque-token-" + i;
                futures.add(executor.submit(() -> {
                    assertThat(start.await(5, TimeUnit.SECONDS), is(true));
                    AuthenticationResponse response = authenticate(provider, token);
                    if (response.statusCode().orElse(-1) == 503) {
                        overloadObserved.countDown();
                    }
                    return response;
                }));
            }

            start.countDown();
            assertThat(introspectionRequestsStarted.await(5, TimeUnit.SECONDS), is(true));
            assertThat(overloadObserved.await(5, TimeUnit.SECONDS), is(true));
            releaseIntrospectionResponses.countDown();

            int succeeded = 0;
            int overloaded = 0;
            for (Future<AuthenticationResponse> future : futures) {
                AuthenticationResponse response = future.get(10, TimeUnit.SECONDS);
                if (response.status() == SecurityResponse.SecurityStatus.SUCCESS) {
                    succeeded++;
                } else if (response.statusCode().orElse(-1) == 503) {
                    overloaded++;
                }
            }
            assertThat(succeeded + overloaded, is(taskCount));
            assertThat(overloaded > 0, is(true));
            assertThat(MAX_ACTIVE_REQUESTS.get() <= maxConcurrent, is(true));
            assertThat(REQUEST_COUNT.get(), is(succeeded));
        } finally {
            releaseIntrospectionResponses.countDown();
        }

        AuthenticationResponse recovered = authenticate(provider, "recovery-token");
        assertThat(recovered.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(ACTIVE_REQUESTS.get(), is(0));
    }

    @Test
    void introspectionRedirectIsNotFollowedWhenTenantWebClientFollowsRedirects() {
        responseStatus = 307;
        redirectLocation = redirectedIntrospectionEndpointUri.toString();
        responseBody = JsonObject.builder()
                .set("error", "temporarily_unavailable")
                .build()
                .toString();

        AuthenticationResponse response = authenticate(
                provider(tenant -> tenant.webClient(redirectFollowingTenantWebClient())),
                OPAQUE_TOKEN);

        assertIntrospectionUnavailable(response);
        assertThat(REDIRECTED_REQUEST_COUNT.get(), is(0));
        assertThat(RECORDED_REQUEST.get().tenantWebClientHeader(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    private static void handleIntrospection(ServerRequest request, ServerResponse response) {
        REQUEST_COUNT.incrementAndGet();
        int active = ACTIVE_REQUESTS.incrementAndGet();
        MAX_ACTIVE_REQUESTS.accumulateAndGet(active, Math::max);
        try {
            RECORDED_REQUEST.set(new RecordedRequest(request.prologue().method().text(),
                                                    request.headers().first(HeaderNames.AUTHORIZATION).orElse(""),
                                                    request.headers().first(HeaderNames.CONTENT_TYPE).orElse(""),
                                                    request.headers().first(TENANT_WEBCLIENT_HEADER_NAME).orElse(""),
                                                    formParameters(request.content().as(Parameters.class))));
            CountDownLatch started = introspectionRequestsStarted;
            if (started != null) {
                started.countDown();
            }
            CountDownLatch release = releaseIntrospectionResponses;
            if (release != null && !release.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to release Introspection Endpoint response");
            }
            response.status(responseStatus);
            introspectionResponseHeaders.forEach(response::header);
            if (responseContentType != null) {
                response.header(HeaderNames.CONTENT_TYPE, responseContentType);
            }
            if (redirectLocation != null) {
                response.header(HeaderNames.LOCATION, redirectLocation);
            }
            response.send(responseBody);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting to release Introspection Endpoint response", e);
        } finally {
            ACTIVE_REQUESTS.decrementAndGet();
        }
    }

    private OidcProvider limitedIntrospectionProvider(Duration readTimeout) {
        return provider(tenant -> tenant
                .webClient(WebClientConfig.builder().readTimeout(readTimeout).buildPrototype())
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION).audience(AUDIENCE)
                        .introspection(introspection -> introspection.remoteWork(work -> work
                                .maxConcurrent(1).maxQueued(0).admissionTimeout(Duration.ZERO))))));
    }

    private void assertJwtIntrospection(OidcClientAuthenticationMethod method,
                                       boolean discoverEndpoint,
                                       boolean separateAssertion) throws Exception {
        URI expectedIssuer = discoverEndpoint ? discoveryIssuer : ISSUER;
        responseBody = validResponse(builder -> builder.set("iss", expectedIssuer.toString())).toString();
        boolean privateKey = method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT;
        String algorithm = (privateKey ? "RS" : "HS") + (separateAssertion ? "512" : "256");
        OidcClientAssertionConfig.Builder assertionBuilder = OidcClientAssertionConfig.builder()
                .algorithm(privateKey ? "RS256" : "HS256");
        if (privateKey) {
            assertionBuilder.jwk(ResourceConfig.builder()
                    .resourcePath("oidc-next-sign-jwk.json")
                    .buildPrototype()).keyId("sign-rsa");
        }
        OidcClientAssertionConfig assertion = assertionBuilder.buildPrototype();
        discoveryResponseBody = JsonObject.builder()
                .set("issuer", expectedIssuer.toString())
                .set("introspection_endpoint", introspectionEndpointUri.toString())
                .setStrings("introspection_endpoint_auth_methods_supported", List.of(method.wireName()))
                .setStrings("introspection_endpoint_auth_signing_alg_values_supported", List.of(algorithm))
                .build()
                .toString();
        OidcProvider provider = provider(tenant -> tenant
                .issuer(expectedIssuer.toString())
                .clientSecret(JWT_CLIENT_SECRET)
                .tokenEndpointAuthenticationMethod(method)
                .clientAssertion(assertion)
                .endpoints(endpoints -> {
                    endpoints.wellKnownUri(introspectionEndpointUri.resolve("/.well-known/openid-configuration"))
                            .tlsRequired(false);
                    if (!discoverEndpoint) {
                        endpoints.introspectionEndpointUri(introspectionEndpointUri);
                    }
                })
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience(AUDIENCE)
                        .introspection(introspection -> {
                            introspection.authenticationMethod(method);
                            if (separateAssertion) {
                                introspection.clientId("introspection-client")
                                        .clientSecret(INTROSPECTION_JWT_SECRET)
                                        .clientAssertion(OidcClientAssertionConfig.builder(assertion)
                                                .algorithm(algorithm)
                                                .lifetime(Duration.ofSeconds(20))
                                                .buildPrototype());
                            }
                        }))));

        AuthenticationResponse first = authenticate(provider, OPAQUE_TOKEN);
        assertThat(first.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(first.user().orElseThrow().principal().id(),
                   is(OidcTestIdentities.issuerSubject(expectedIssuer.toString(), SUBJECT)));
        SignedJwt firstAssertion = verifiedIntrospectionAssertion(method, separateAssertion, algorithm);
        AuthenticationResponse second = authenticate(provider, OPAQUE_TOKEN);
        assertThat(second.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        SignedJwt secondAssertion = verifiedIntrospectionAssertion(method, separateAssertion, algorithm);
        assertThat(secondAssertion.getJwt().jwtId(), not(firstAssertion.getJwt().jwtId()));
        assertThat(REQUEST_COUNT.get(), is(2));
        assertThat(DISCOVERY_REQUEST_COUNT.get(), is(discoverEndpoint ? 1 : 0));
    }

    private SignedJwt verifiedIntrospectionAssertion(OidcClientAuthenticationMethod method,
                                                     boolean separateAssertion,
                                                     String algorithm) throws Exception {
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.method(), is("POST"));
        assertThat(request.contentType(), is("application/x-www-form-urlencoded"));
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters().containsKey("client_secret"), is(false));
        assertThat(request.formParameters().get("token"), is(List.of(OPAQUE_TOKEN)));
        assertThat(request.formParameters().get("client_assertion_type"),
                   is(List.of("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")));
        String encoded = request.formParameters().get("client_assertion").getFirst();
        SignedJWT independent = SignedJWT.parse(encoded);
        if (method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT) {
            JwkRSA key = (JwkRSA) JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json"))
                    .build().forKeyId("sign-rsa").orElseThrow();
            assertThat(independent.verify(new RSASSAVerifier((RSAPublicKey) key.publicKey())), is(true));
        } else {
            String secret = separateAssertion ? INTROSPECTION_JWT_SECRET : JWT_CLIENT_SECRET;
            assertThat(independent.verify(new MACVerifier(secret.getBytes(StandardCharsets.UTF_8))), is(true));
        }
        SignedJwt assertion = SignedJwt.parseToken(encoded);
        String clientId = separateAssertion ? "introspection-client" : CLIENT_ID;
        assertThat(assertion.getJwt().algorithm().orElseThrow(), is(algorithm));
        assertThat(assertion.getJwt().issuer().orElseThrow(), is(clientId));
        assertThat(assertion.getJwt().subject().orElseThrow(), is(clientId));
        assertThat(assertion.getJwt().audience().orElseThrow(), is(List.of(introspectionEndpointUri.toString())));
        assertThat(Duration.between(assertion.getJwt().issueTime().orElseThrow(),
                                   assertion.getJwt().expirationTime().orElseThrow()),
                   is(separateAssertion ? Duration.ofSeconds(20) : Duration.ofMinutes(1)));
        assertThat(assertion.getJwt().jwtId().orElseThrow().isBlank(), is(false));
        return assertion;
    }

    private AuthenticationResponse authenticate(OidcProvider provider, String token) {
        return provider.authenticate(OidcProviderTest.request(null,
                                                              SecurityEnvironment.builder()
                                                                      .targetUri(URI.create("https://rp.example/resource"))
                                                                      .header("Authorization", "Bearer " + token)
                                                                      .build()));
    }

    private AuthenticationResponse authenticate(OidcProvider provider, String token, Certificate certificate) {
        return provider.authenticate(OidcProviderTest.request(null,
                                                              SecurityEnvironment.builder()
                                                                      .targetUri(URI.create("https://rp.example/resource"))
                                                                      .header("Authorization", "Bearer " + token)
                                                                      .addAttribute("remotePeer",
                                                                                    OidcTestCertificates.peerInfo(
                                                                                            certificate))
                                                                      .build()));
    }

    private OidcProvider provider() {
        return provider(true);
    }

    private OidcProvider provider(boolean audienceValidationEnabled) {
        return provider(audienceValidationEnabled, true);
    }

    private OidcProvider provider(boolean audienceValidationEnabled, boolean audienceConfigured) {
        return provider(audienceValidationEnabled, audienceConfigured, _ -> { });
    }

    private OidcProvider provider(Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        return provider(true, true, tenantCustomizer);
    }

    private OidcProvider provider(OidcCertificateBoundAccessTokenMode certificateBoundAccessTokenMode) {
        return provider(tenant -> tenant.protectedResource(resource -> resource
                .tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience(AUDIENCE)
                        .certificateBoundAccessTokens(certificateBound -> certificateBound
                                .mode(certificateBoundAccessTokenMode)))));
    }

    private OidcProvider provider(boolean audienceValidationEnabled,
                                  boolean audienceConfigured,
                                  Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig.Builder tenantBuilder = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it
                        .introspectionEndpointUri(introspectionEndpointUri)
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> {
                            validation
                                    .method(OidcTokenValidationMethod.INTROSPECTION)
                                    .audienceValidationEnabled(audienceValidationEnabled);
                            if (audienceConfigured) {
                                validation.audience(AUDIENCE);
                            }
                        }));
        tenantCustomizer.accept(tenantBuilder);
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenantBuilder.buildPrototype())
                                           .buildPrototype());
    }

    private static OidcTenantConfig introspectionTenant(OidcClientAuthenticationMethod authenticationMethod,
                                                        URI introspectionEndpointUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.introspectionEndpointUri(introspectionEndpointUri)
                        .tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience(AUDIENCE)
                        .introspection(introspection -> introspection.authenticationMethod(authenticationMethod))))
                .buildPrototype();
    }

    private static WebClientConfig mutualTlsWebClient() {
        Keys privateKeyConfig = Keys.builder()
                .keystore(store -> store
                        .passphrase("password")
                        .keystore(Resource.create("client.p12")))
                .build();
        return WebClientConfig.builder()
                .tls(tls -> tls
                        .privateKey(privateKeyConfig)
                        .privateKeyCertChain(privateKeyConfig))
                .buildPrototype();
    }

    private static WebClientConfig tenantWebClient() {
        return WebClientConfig.builder()
                .addHeader(TENANT_WEBCLIENT_HEADER, TENANT_WEBCLIENT_HEADER_VALUE)
                .buildPrototype();
    }

    private static WebClientConfig redirectFollowingTenantWebClient() {
        return WebClientConfig.builder()
                .addHeader(TENANT_WEBCLIENT_HEADER, TENANT_WEBCLIENT_HEADER_VALUE)
                .followRedirects(true)
                .buildPrototype();
    }

    private static JsonObject validResponse(Consumer<JsonObject.Builder> customizer) {
        Instant now = Instant.now();
        JsonObject.Builder builder = JsonObject.builder()
                .set("active", true)
                .set("sub", SUBJECT)
                .set("username", USERNAME)
                .set("preferred_username", USERNAME)
                .set("email", "user1@example.org")
                .set("iss", ISSUER.toString())
                .setStrings("aud", List.of(AUDIENCE))
                .set("exp", now.plus(1, ChronoUnit.HOURS).getEpochSecond())
                .set("iat", now.minus(1, ChronoUnit.MINUTES).getEpochSecond())
                .set("nbf", now.minus(1, ChronoUnit.MINUTES).getEpochSecond())
                .set("scope", "resource.read resource.write")
                .setStrings("groups", List.of("admin", "auditor"))
                .set("client_id", "calling-client")
                .set("token_type", "Bearer");
        customizer.accept(builder);
        return builder.build();
    }

    private static String basicAuthorization() {
        byte[] credentials = (formEncode(CLIENT_ID) + ":" + formEncode(CLIENT_SECRET))
                .getBytes(StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder()
                .encodeToString(credentials);
    }

    private static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static void assertIntrospectionUnavailable(AuthenticationResponse response) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(503));
        assertThat(response.description().orElseThrow(), is("Bearer Token validation is unavailable"));
        assertThat(response.user().isEmpty(), is(true));
        assertThat(response.service().isEmpty(), is(true));
        for (HeaderName header : List.of(HeaderNames.WWW_AUTHENTICATE, HeaderNames.SET_COOKIE,
                                         HeaderNames.LOCATION, HeaderNames.RETRY_AFTER)) {
            assertThat(response.responseHeaders().containsKey(header.defaultCase()), is(false));
        }
    }

    private static void assertInvalidToken(AuthenticationResponse response, String ignoredDescription) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.description().orElse(""), is("Bearer Token is invalid"));
        assertThat(response.responseHeaders().get("WWW-Authenticate").getFirst(),
                   is("Bearer realm=\"helidon\", error=\"invalid_token\", "
                              + "error_description=\"Bearer Token is invalid\""));
        assertThat(response.responseHeaders().containsKey("Location"), is(false));
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
                                   String tenantWebClientHeader,
                                   Map<String, List<String>> formParameters) {
    }
}
