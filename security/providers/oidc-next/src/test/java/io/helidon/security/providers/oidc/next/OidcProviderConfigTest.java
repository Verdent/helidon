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
import java.util.function.Consumer;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;

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
        OidcTokenTransportConfig tokenTransport = OidcTokenTransportConfig.create();
        OidcTokenValidationConfig tokenValidation = OidcTokenValidationConfig.create();

        assertThat(providerConfig.providerName(), is("oidc-next"));
        assertThat(providerConfig.optional(), is(false));
        assertThat(providerConfig.tenants().isEmpty(), is(true));
        assertThat(tenantConfig.enabled(), is(true));
        assertThat(authorizationCode.enabled(), is(false));
        assertThat(authorizationCode.scopes(), is(List.of("openid")));
        assertThat(authorizationCode.pkceRequired(), is(true));
        assertThat(authorizationCode.pkceMethod(), is(OidcPkceMethod.S256));
        assertThat(tokenTransport.authorizationHeaderEnabled(), is(true));
        assertThat(tokenTransport.queryParameterEnabled(), is(false));
        assertThat(tokenValidation.audienceValidationEnabled(), is(true));
        assertThat(tokenValidation.allowedAlgorithms(), is(List.of("RS256")));
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
                .sources(ConfigSources.create(Map.of(
                        "tenants.default.issuer", ISSUER.toString(),
                        "tenants.default.client-id", "client-id",
                        "tenants.default.client-secret", "client-secret-value",
                        "tenants.default.endpoints.jwks-uri", JWKS_URI.toString(),
                        "tenants.default.protected-resource.enabled", "true",
                        "tenants.default.protected-resource.token-validation.method", "JWT",
                        "tenants.default.protected-resource.token-validation.audience", AUDIENCE)))
                .build();

        OidcProviderConfig providerConfig = OidcProviderConfig.create(config);

        assertThat(providerConfig.defaultTenant().orElse(""), is("default"));
        OidcTenantConfig tenant = providerConfig.tenants().get("default");
        assertThat(tenant.issuer().orElseThrow(), is(ISSUER));
        assertThat(tenant.clientId().orElse(""), is("client-id"));
        assertThat(tenant.endpoints().jwksUri().orElseThrow(), is(JWKS_URI));
        assertThat(tenant.protectedResource().enabled(), is(true));
        assertThat(tenant.protectedResource().tokenValidation().method().orElseThrow(),
                   is(OidcTokenValidationMethod.JWT));
        assertThat(tenant.protectedResource().tokenValidation().audience().orElse(""), is(AUDIENCE));
    }

    @Test
    void disabledTenantCanKeepIncompleteFlowConfiguration() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .enabled(false)
                .protectedResource(it -> it.enabled(true))
                .authorizationCode(it -> it.enabled(true))
                .outbound(it -> it.clientCredentialsGrantEnabled(true))
                .buildPrototype();

        assertThat(tenant.enabled(), is(false));
        assertThat(tenant.protectedResource().enabled(), is(true));
        assertThat(tenant.authorizationCode().enabled(), is(true));
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
    void protectedResourceRequiresValidationMethod() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.enabled(true))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.method"));
    }

    @Test
    void jwtValidationRequiresIssuerAndJwks() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("issuer"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("jwks-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.discoveryUri(DISCOVERY_URI))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("jwks-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.audience"));
    }

    @Test
    void jwtValidationRequiresSecureJwksUriScheme() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(URI.create("http://issuer.example/jwks")))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
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
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void jwtValidationCanExplicitlyDisableAudienceValidation() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audienceValidationEnabled(false)))
                .buildPrototype();

        assertThat(tenant.protectedResource().tokenValidation().audience().isEmpty(), is(true));
        assertThat(tenant.protectedResource().tokenValidation().audienceValidationEnabled(), is(false));
    }

    @Test
    void audienceCanBeDisabledFromConfig() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.of(
                        "tenants.default.issuer", ISSUER.toString(),
                        "tenants.default.endpoints.jwks-uri", JWKS_URI.toString(),
                        "tenants.default.protected-resource.enabled", "true",
                        "tenants.default.protected-resource.token-validation.method", "JWT",
                        "tenants.default.protected-resource.token-validation.audience-validation-enabled", "false")))
                .build();

        OidcTokenValidationConfig tokenValidation = OidcProviderConfig.create(config)
                .tenants()
                .get("default")
                .protectedResource()
                .tokenValidation();

        assertThat(tokenValidation.audience().isEmpty(), is(true));
        assertThat(tokenValidation.audienceValidationEnabled(), is(false));
    }

    @Test
    void introspectionRequiresEndpointAndClientAuthentication() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("introspection-endpoint-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-secret"));
    }

    @Test
    void introspectionRequiresAudienceWhenAudienceValidationIsEnabled() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.audience"));
    }

    @Test
    void introspectionRejectsDiscoveryOnlyUntilDiscoveryLoadingExists() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.discoveryUri(URI.create("https://issuer.example/.well-known/openid-configuration")))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)
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
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)
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
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)
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
                .authorizationCode(it -> it.enabled(true))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://issuer.example/authorize"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.enabled(true))
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
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
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
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
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
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
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
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void authorizationCodeFlowRejectsAuthorizationEndpointWithFragment() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://issuer.example/authorize#fragment"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
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
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .pkceRequired(false))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.authorizationCode().pkceRequired(), is(false));
        assertThat(tenant.authorizationCode().pkceMethod(), is(OidcPkceMethod.S256));
    }

    @Test
    void authorizationCodeFlowCanUseDiscoveryUriDerivedFromIssuer() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
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
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
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
    void clientCredentialsGrantRequiresClientAuthenticationAndTokenEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .outbound(it -> it.clientCredentialsGrantEnabled(true))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
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
        assertThat(metadata, containsString("path-template"));
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
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
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
