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

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.providers.common.OutboundTarget;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcProviderConfigTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI DISCOVERY_URI = URI.create("https://issuer.example/.well-known/openid-configuration");
    private static final URI JWKS_URI = URI.create("https://issuer.example/jwks");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final String AUDIENCE = "api://default";

    @Test
    void defaultsAreSecureAndSpecFirst() {
        OidcProviderConfig providerConfig = OidcProviderConfig.create();
        OidcTenantConfig tenantConfig = OidcTenantConfig.create();
        OidcAuthorizationCodeConfig authorizationCode = OidcAuthorizationCodeConfig.create();
        OidcProtectedResourceConfig protectedResource = OidcProtectedResourceConfig.create();
        OidcTokenTransportConfig tokenTransport = OidcTokenTransportConfig.create();
        OidcTokenValidationConfig tokenValidation = OidcTokenValidationConfig.create();
        OidcCookieConfig cookies = OidcCookieConfig.create();
        OidcSubjectMappingConfig subjectMapping = OidcSubjectMappingConfig.create();

        assertThat(providerConfig.providerName(), is("oidc-next"));
        assertThat(providerConfig.optional(), is(false));
        assertThat(providerConfig.tenants().isEmpty(), is(true));
        assertThat(providerConfig.outboundTargets().isEmpty(), is(true));
        assertThat(tenantConfig.enabled(), is(true));
        assertThat(tenantConfig.protectedResource().isEmpty(), is(true));
        assertThat(tenantConfig.authorizationCode().isEmpty(), is(true));
        assertThat(authorizationCode.enabled(), is(true));
        assertThat(protectedResource.enabled(), is(true));
        assertThat(authorizationCode.scopes(), is(List.of("openid")));
        assertThat(authorizationCode.pkceRequired(), is(true));
        assertThat(authorizationCode.pkceMethod(), is(OidcPkceMethod.S256));
        assertThat(tokenTransport.authorizationHeaderEnabled(), is(true));
        assertThat(tokenTransport.queryParameterEnabled(), is(false));
        assertThat(tokenValidation.audienceValidationEnabled(), is(true));
        assertThat(tokenValidation.allowedAlgorithms(), is(List.of("RS256")));
        assertThat(subjectMapping.principalIdClaimPaths(), is(List.of("sub", "username", "client_id")));
        assertThat(subjectMapping.principalNameClaimPaths(), is(List.of("preferred_username", "username")));
        assertThat(subjectMapping.roleClaimPaths(), is(List.of("groups")));
        assertThat(subjectMapping.scopeClaimPaths(), is(List.of("scope")));
        assertThat(subjectMapping.scopeGrantsEnabled(), is(true));
        assertThat(tenantConfig.subjectMapping().principalIdClaimPaths(), is(subjectMapping.principalIdClaimPaths()));
        assertThat(cookies.authenticationRequestCookieName(), is("__Host-helidon-oidc-state"));
        assertThat(cookies.localAuthenticationCookieName(), is("__Host-helidon-oidc-auth"));
        assertThat(OidcPkceMethod.values().length, is(1));
        assertThat(OidcPkceMethod.values()[0], is(OidcPkceMethod.S256));
    }

    @Test
    void providerConfigCreatesImmutableValuesAndHidesSecrets() {
        OidcTenantConfig tenant = jwtProtectedResourceTenant();

        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .tenants(Map.of("default", tenant))
                .buildPrototype();

        assertThat(providerConfig.defaultTenant().orElse(""), is("default"));
        assertThat(providerConfig.tenants().get("default").clientId().orElse(""), is("client-id"));
        assertThat(providerConfig.toString().contains("client-secret-value"), is(false));
        assertThrows(UnsupportedOperationException.class, () -> providerConfig.tenants().put("other", tenant));
    }

    @Test
    void providerConfigCanBeReadFromConfig() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.issuer", ISSUER.toString()),
                        Map.entry("tenants.default.client-id", "client-id"),
                        Map.entry("tenants.default.client-secret", "client-secret-value"),
                        Map.entry("tenants.default.endpoints.jwks-uri", JWKS_URI.toString()),
                        Map.entry("tenants.default.protected-resource.token-validation.method", "JWT"),
                        Map.entry("tenants.default.protected-resource.token-validation.audience", AUDIENCE),
                        Map.entry("tenants.default.subject-mapping.principal-id-claim-paths.0", "custom_sub"),
                        Map.entry("tenants.default.subject-mapping.principal-id-claim-paths.1", "sub"),
                        Map.entry("tenants.default.subject-mapping.principal-name-claim-paths.0", "display_name"),
                        Map.entry("tenants.default.subject-mapping.role-claim-paths.0", "realm_access.roles"),
                        Map.entry("tenants.default.subject-mapping.scope-claim-paths.0", "scp"),
                        Map.entry("tenants.default.subject-mapping.scope-grants-enabled", "false"),
                        Map.entry("outbound.0.name", "orders"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/orders/.*"))))
                .build();

        OidcProviderConfig providerConfig = OidcProviderConfig.create(config);

        assertThat(providerConfig.defaultTenant().orElse(""), is("default"));
        OutboundTarget outboundTarget = providerConfig.outboundTargets().getFirst();
        assertThat(outboundTarget.name(), is("orders"));
        assertThat(outboundTarget.hosts(), is(Set.of("api.example.com")));
        OidcTenantConfig tenant = providerConfig.tenants().get("default");
        assertThat(tenant.issuer().orElseThrow(), is(ISSUER));
        assertThat(tenant.clientId().orElse(""), is("client-id"));
        assertThat(tenant.endpoints().jwksUri().orElseThrow(), is(JWKS_URI));
        OidcProtectedResourceConfig protectedResource = tenant.protectedResource().orElseThrow();
        assertThat(protectedResource.enabled(), is(true));
        assertThat(protectedResource.tokenValidation().method().orElseThrow(),
                   is(OidcTokenValidationMethod.JWT));
        assertThat(protectedResource.tokenValidation().audience().orElse(""), is(AUDIENCE));
        assertThat(tenant.subjectMapping().principalIdClaimPaths(), is(List.of("custom_sub", "sub")));
        assertThat(tenant.subjectMapping().principalNameClaimPaths(), is(List.of("display_name")));
        assertThat(tenant.subjectMapping().roleClaimPaths(), is(List.of("realm_access.roles")));
        assertThat(tenant.subjectMapping().scopeClaimPaths(), is(List.of("scp")));
        assertThat(tenant.subjectMapping().scopeGrantsEnabled(), is(false));
    }

    @Test
    void disabledTenantCanKeepIncompleteFlowConfiguration() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .enabled(false)
                .protectedResource(OidcProtectedResourceConfig.create())
                .authorizationCode(OidcAuthorizationCodeConfig.create())
                .outbound(it -> it.clientCredentialsGrantEnabled(true))
                .buildPrototype();

        assertThat(tenant.enabled(), is(false));
        assertThat(tenant.protectedResource().orElseThrow().enabled(), is(true));
        assertThat(tenant.authorizationCode().orElseThrow().enabled(), is(true));
        assertThat(tenant.outbound().clientCredentialsGrantEnabled(), is(true));
    }

    @Test
    void tenantResolutionConfigRejectsInvalidValues() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantResolutionConfig.builder()
                                                               .headerName(" ")
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("header-name"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .pathSegment(-1)
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("path-segment"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .pathTemplate(" ")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("path-template"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .pathTemplate("/tenants/{tenant}/{tenant}")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("{tenant}"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .pathTemplate("/tenants/tenant-{tenant}")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("complete path segment"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .hostTemplate(" ")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("host-template"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .hostTemplate("example.com")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("{tenant}"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .hostTemplate("{tenant}.{tenant}.example.com")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("{tenant}"));
    }

    @Test
    void subjectMappingConfigRejectsInvalidClaimPaths() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .subjectMapping(it -> it.principalIdClaimPaths(List.of()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("subject-mapping.principal-id-claim-paths"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .subjectMapping(it -> it.principalIdClaimPaths(List.of(" ")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("subject-mapping.principal-id-claim-paths"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .subjectMapping(it -> it.roleClaimPaths(List.of("realm_access..roles")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("subject-mapping.role-claim-paths"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .subjectMapping(it -> it.roleClaimPaths(List.of("realm_access. roles")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("subject-mapping.role-claim-paths"));
    }

    @Test
    void protectedResourceRequiresValidationMethod() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(OidcProtectedResourceConfig.create())
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.method"));
    }

    @Test
    void jwtValidationRequiresIssuerOrDiscoveryAndJwksOrDiscovery() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("issuer or discovery-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.audience"));

        OidcTenantConfig derivedDiscoveryTenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();
        assertThat(derivedDiscoveryTenant.endpoints().jwksUri().isEmpty(), is(true));

        OidcTenantConfig explicitDiscoveryTenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.discoveryUri(DISCOVERY_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();
        assertThat(explicitDiscoveryTenant.endpoints().jwksUri().isEmpty(), is(true));

        OidcTenantConfig discoveryOnlyTenant = OidcTenantConfig.builder()
                .endpoints(it -> it.discoveryUri(DISCOVERY_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();
        assertThat(discoveryOnlyTenant.issuer().isEmpty(), is(true));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.audience"));
    }

    @Test
    void tokenValidationMethodRequiresPrerequisitesWithoutProtectedResource() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .protectedResource(it -> it.enabled(false)
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("issuer or discovery-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .clientSecret("client-secret")
                .protectedResource(it -> it.enabled(false)
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("introspection-endpoint-uri"));
    }

    @Test
    void jwtValidationRequiresSecureJwksUriScheme() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(URI.create("http://issuer.example/jwks")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("jwks-uri must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForJwksUri() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(URI.create("file:///tmp/oidc-next-jwks.json"))
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void jwtValidationCanExplicitlyDisableAudienceValidation() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audienceValidationEnabled(false)))
                .buildPrototype();

        OidcTokenValidationConfig tokenValidation = tenant.protectedResource().orElseThrow().tokenValidation();
        assertThat(tokenValidation.audience().isEmpty(), is(true));
        assertThat(tokenValidation.audienceValidationEnabled(), is(false));
    }

    @Test
    void audienceCanBeDisabledFromConfig() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.of(
                        "tenants.default.issuer", ISSUER.toString(),
                        "tenants.default.endpoints.jwks-uri", JWKS_URI.toString(),
                        "tenants.default.protected-resource.token-validation.method", "JWT",
                        "tenants.default.protected-resource.token-validation.audience-validation-enabled", "false")))
                .build();

        OidcTokenValidationConfig tokenValidation = OidcProviderConfig.create(config)
                .tenants()
                .get("default")
                .protectedResource()
                .orElseThrow()
                .tokenValidation();

        assertThat(tokenValidation.audience().isEmpty(), is(true));
        assertThat(tokenValidation.audienceValidationEnabled(), is(false));
    }

    @Test
    void introspectionRequiresEndpointAndClientAuthentication() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("introspection-endpoint-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-secret"));
    }

    @Test
    void introspectionRequiresAudienceWhenAudienceValidationIsEnabled() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.audience"));
    }

    @Test
    void introspectionRejectsDiscoveryOnlyUntilDiscoveryLoadingExists() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.discoveryUri(URI.create("https://issuer.example/.well-known/openid-configuration")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience("api://default")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("introspection-endpoint-uri"));
    }

    @Test
    void introspectionRejectsInsecureRemoteEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("http://issuer.example/introspect")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience("api://default")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("introspection-endpoint-uri must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForIntrospection() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("http://issuer.example/introspect"))
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience("api://default")))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void authorizationCodeFlowRequiresRedirectionEndpointAndClient() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://issuer.example/authorize"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(OidcAuthorizationCodeConfig.create())
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://issuer.example/authorize"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(OidcAuthorizationCodeConfig.create())
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("redirection-endpoint-uri"));
    }

    @Test
    void authorizationCodeFlowRequiresOpenIdScope() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("email")))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("openid scope"));
    }

    @Test
    void authorizationCodeFlowRequiresCookieEncryptionSecret() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("cookies.encryption-secret"));
    }

    @Test
    void authorizationCodeFlowRejectsInsecureAuthorizationEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("http://issuer.example/authorize"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authorization-endpoint-uri must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForAuthorizationEndpoint() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("http://issuer.example/authorize"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void authorizationCodeFlowRejectsInsecureTokenEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(URI.create("http://issuer.example/token")))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForTokenEndpoint() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(URI.create("http://issuer.example/token"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void authorizationCodeFlowRejectsTokenEndpointWithFragment() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(URI.create("https://issuer.example/token#fragment")))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must not include a fragment"));
    }

    @Test
    void authorizationCodeFlowRejectsAuthorizationEndpointWithFragment() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://issuer.example/authorize#fragment"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authorization-endpoint-uri must not include a fragment"));
    }

    @Test
    void authorizationCodeFlowCanExplicitlyDisablePkce() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .pkceRequired(false))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcAuthorizationCodeConfig authorizationCode = tenant.authorizationCode().orElseThrow();
        assertThat(authorizationCode.pkceRequired(), is(false));
        assertThat(authorizationCode.pkceMethod(), is(OidcPkceMethod.S256));
    }

    @Test
    void authorizationCodeFlowCanUseClientSecretPostTokenEndpointAuthentication() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_POST)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.tokenEndpointAuthenticationMethod()
                           .orElseThrow(),
                   is(OidcClientAuthenticationMethod.CLIENT_SECRET_POST));
    }

    @Test
    void authorizationCodeFlowRequiresClientSecretForSecretTokenEndpointAuthentication() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-secret"));
    }

    @Test
    void authorizationCodeFlowCanUseDiscoveryUriDerivedFromIssuer() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.endpoints().discoveryUri().isEmpty(), is(true));
    }

    @Test
    void protectedResourceRequiresUsableTokenTransport() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .tokenTransport(it -> it.authorizationHeaderEnabled(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("Bearer Token transport"));
    }

    @Test
    void tokenTransportConfigDrivesStageOneBearerEvidence() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .tenants(Map.of("default", jwtProtectedResourceTenant(it -> it
                                                          .authorizationHeaderEnabled(false)
                                                          .queryParameterEnabled(true))))
                                                  .buildPrototype());

        var headerResponse = provider.authenticate(OidcProviderTest.request(null,
                                                                            SecurityEnvironment.builder()
                                                                                    .header("Authorization",
                                                                                            "Bearer access-token")
                                                                                    .build()));
        var queryResponse = provider.authenticate(OidcProviderTest.request(null,
                                                                           SecurityEnvironment.builder()
                                                                                   .queryParam("access_token",
                                                                                               "access-token")
                                                                                   .build()));

        assertThat(headerResponse.description().orElse(""), is("Bearer Token is required"));
        assertThat(queryResponse.description().orElse(""), is("Bearer Token is not a valid signed JWT"));
    }

    @Test
    void defaultTenantMustReferenceConfiguredTenant() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcProviderConfig.builder()
                                                               .defaultTenant("missing")
                                                               .putTenant("default", jwtProtectedResourceTenant())
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("default-tenant"));
    }

    @Test
    void tenantWideOutboundOperationsCannotBeAmbiguous() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .outbound(it -> it.tokenPropagationEnabled(true)
                        .clientCredentialsGrantEnabled(true))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("Token Propagation and Client Credentials Grant"));
    }

    @Test
    void outboundTargetOperationsCannotBeAmbiguous() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundTargetConfig.builder()
                                                               .tokenPropagationEnabled(true)
                                                               .clientCredentialsGrantEnabled(true)
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("Token Propagation and Client Credentials Grant"));
    }

    @Test
    void clientCredentialsGrantRequiresClientAuthenticationAndTokenEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .outbound(it -> it.clientCredentialsGrantEnabled(true))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .outbound(it -> it.clientCredentialsGrantEnabled(true))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("Token Endpoint authentication"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .outbound(it -> it.clientCredentialsGrantEnabled(true))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-secret"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .outbound(it -> it.clientCredentialsGrantEnabled(true))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri"));
    }

    @Test
    void targetClientCredentialsGrantRequiresClientAuthenticationAndTlsTokenEndpoint() {
        Config noneAuthenticationConfig = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", "client-id"),
                        Map.entry("tenants.default.token-endpoint-auth-method", "NONE"),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", TOKEN_ENDPOINT_URI.toString()),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"))))
                .build();

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcProviderConfig.create(noneAuthenticationConfig));

        assertThat(thrown.getMessage(), containsString("Token Endpoint authentication cannot be NONE"));

        Config insecureTokenEndpointConfig = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", "client-id"),
                        Map.entry("tenants.default.client-secret", "client-secret-value"),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", "http://issuer.example/token"),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"))))
                .build();

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcProviderConfig.create(insecureTokenEndpointConfig));

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must use https"));
    }

    @Test
    void providerConfigDrivesStageOneClassificationDefaults() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .tenants(Map.of("default", jwtProtectedResourceTenant()))
                                                  .buildPrototype());

        var response = provider.authenticate(OidcProviderTest.request(null, SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
    }

    @Test
    void optionalProviderBehaviorAbstainsWhenCredentialIsMissing() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .optional(true)
                                                  .tenants(Map.of("default", jwtProtectedResourceTenant()))
                                                  .buildPrototype());

        var response = provider.authenticate(OidcProviderTest.request(null, SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(response.description().orElse(""), is("Bearer Token is required"));
    }

    @Test
    void generatedConfigMetadataContainsNewModel() throws IOException {
        String metadata = configMetadata();

        assertThat(metadata, containsString("oidc-next"));
        assertThat(metadata, containsString("redirection-endpoint-uri"));
        assertThat(metadata, containsString("query-parameter-enabled"));
        assertThat(metadata, containsString("token-validation"));
        assertThat(metadata, containsString("client-credentials-grant-enabled"));
        assertThat(metadata.contains("form-encoded-body-enabled"), is(false));
        assertThat(metadata, containsString("pkce-required"));
        assertThat(metadata, containsString("audience-validation-enabled"));
        assertThat(metadata, containsString("tls-required"));
        assertThat(metadata, containsString("token-endpoint-auth-method"));
        assertThat(metadata, containsString("path-template"));
        assertThat(metadata, containsString("subject-mapping"));
        assertThat(metadata, containsString("principal-id-claim-paths"));
        assertThat(metadata, containsString("role-claim-paths"));
        assertThat(metadata, containsString("scope-grants-enabled"));
    }

    private static OidcTenantConfig jwtProtectedResourceTenant() {
        return jwtProtectedResourceTenant(it -> { });
    }

    private static OidcTenantConfig jwtProtectedResourceTenant(
            Consumer<OidcTokenTransportConfig.Builder> tokenTransport) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .tokenTransport(tokenTransport)
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();
    }

    private static String configMetadata() throws IOException {
        String resource = "META-INF/helidon/config-metadata.json";
        Enumeration<java.net.URL> resources = OidcProviderConfigTest.class.getClassLoader().getResources(resource);
        StringBuilder metadata = new StringBuilder();
        while (resources.hasMoreElements()) {
            try (var stream = resources.nextElement().openStream()) {
                metadata.append(new String(stream.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
        return metadata.toString();
    }
}
