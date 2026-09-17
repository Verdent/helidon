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
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

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

    private static int responseStatus;
    private static String responseBody;
    private static String responseContentType;
    private static String redirectLocation;
    private static final AtomicInteger REDIRECTED_REQUEST_COUNT = new AtomicInteger();
    private static final AtomicInteger REQUEST_COUNT = new AtomicInteger();
    private static final AtomicInteger ACTIVE_REQUESTS = new AtomicInteger();
    private static final AtomicInteger MAX_ACTIVE_REQUESTS = new AtomicInteger();
    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();
    private static volatile CountDownLatch introspectionRequestsStarted;
    private static volatile CountDownLatch releaseIntrospectionResponses;

    private URI introspectionEndpointUri;
    private URI redirectedIntrospectionEndpointUri;

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
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
        responseStatus = 200;
        responseBody = validResponse(_ -> { }).toString();
        responseContentType = "application/json";
        redirectLocation = null;
        REDIRECTED_REQUEST_COUNT.set(0);
        REQUEST_COUNT.set(0);
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

        OidcTenantConfig conventionalTenant = introspectionTenant(
                OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                conventionalIntrospectionEndpointUri);
        assertThat(OidcIntrospectionAccessTokenValidator.introspectionEndpointUri(
                           metadata,
                           OidcClientAuthenticationSupport.introspectionEndpoint(conventionalTenant)),
                   is(Optional.of(conventionalIntrospectionEndpointUri)));
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

        assertInvalidToken(response, "Principal claim must not be changed by UTF-8 replacement");
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

        assertInvalidToken(response, "Bearer Token introspection response is invalid");
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

        assertInvalidToken(response, "Bearer Token introspection response is invalid");
    }

    @Test
    void stringNumericDateIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("nbf", "1773000000")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response is invalid");
    }

    @Test
    void outOfRangeNumericDateIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("iat", BigDecimal.valueOf(Long.MAX_VALUE)
                .add(BigDecimal.ONE))).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response is invalid");
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

        assertInvalidToken(response, "Bearer Token introspection response is invalid");
    }

    @Test
    void introspectionResponseWithoutJsonContentTypeIsRejected() {
        responseContentType = "text/plain";

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response is invalid");
    }

    @Test
    void nonSuccessfulIntrospectionResponseIsRejected() {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid_request")
                .build()
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection endpoint rejected the token");
    }

    @Test
    void unavailableIntrospectionEndpointIsRejected() {
        responseStatus = 503;
        responseBody = JsonObject.builder()
                .set("error", "temporarily_unavailable")
                .build()
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection endpoint is unavailable");
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
        OidcProvider provider = provider(tenant -> tenant.protectedResource(resource -> resource
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

        assertInvalidToken(response, "Bearer Token introspection endpoint rejected the token");
        assertThat(REDIRECTED_REQUEST_COUNT.get(), is(0));
        assertThat(RECORDED_REQUEST.get().tenantWebClientHeader(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    private static void handleIntrospection(ServerRequest request, ServerResponse response) {
        REQUEST_COUNT.incrementAndGet();
        int active = ACTIVE_REQUESTS.incrementAndGet();
        MAX_ACTIVE_REQUESTS.accumulateAndGet(active, Math::max);
        try {
            CountDownLatch started = introspectionRequestsStarted;
            if (started != null) {
                started.countDown();
            }
            CountDownLatch release = releaseIntrospectionResponses;
            if (release != null && !release.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to release Introspection Endpoint response");
            }
            RECORDED_REQUEST.set(new RecordedRequest(request.prologue().method().text(),
                                                    request.headers().first(HeaderNames.AUTHORIZATION).orElse(""),
                                                    request.headers().first(HeaderNames.CONTENT_TYPE).orElse(""),
                                                    request.headers().first(TENANT_WEBCLIENT_HEADER_NAME).orElse(""),
                                                    formParameters(request.content().as(Parameters.class))));
            response.status(responseStatus);
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
