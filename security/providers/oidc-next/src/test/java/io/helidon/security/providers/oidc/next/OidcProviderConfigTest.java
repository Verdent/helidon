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
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");

    @Test
    void defaultsAreSecureAndSpecFirst() {
        OidcProviderConfig providerConfig = OidcProviderConfig.create();
        OidcAuthorizationCodeConfig authorizationCode = OidcAuthorizationCodeConfig.create();
        OidcTokenTransportConfig tokenTransport = OidcTokenTransportConfig.create();
        OidcTokenValidationConfig tokenValidation = OidcTokenValidationConfig.create();

        assertThat(providerConfig.providerName(), is("oidc-next"));
        assertThat(providerConfig.optional(), is(false));
        assertThat(providerConfig.tenants().isEmpty(), is(true));
        assertThat(authorizationCode.enabled(), is(false));
        assertThat(authorizationCode.scopes(), is(List.of("openid")));
        assertThat(authorizationCode.pkceRequired(), is(true));
        assertThat(authorizationCode.pkceMethod(), is(OidcPkceMethod.S256));
        assertThat(tokenTransport.authorizationHeaderEnabled(), is(true));
        assertThat(tokenTransport.formEncodedBodyEnabled(), is(false));
        assertThat(tokenTransport.queryParameterEnabled(), is(false));
        assertThat(tokenValidation.allowedAlgorithms(), is(List.of("RS256")));
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
                        "tenants.default.endpoints.discovery-uri", DISCOVERY_URI.toString(),
                        "tenants.default.protected-resource.enabled", "true",
                        "tenants.default.protected-resource.token-validation.method", "JWT")))
                .build();

        OidcProviderConfig providerConfig = OidcProviderConfig.create(config);

        assertThat(providerConfig.defaultTenant().orElse(""), is("default"));
        OidcTenantConfig tenant = providerConfig.tenants().get("default");
        assertThat(tenant.issuer().orElseThrow(), is(ISSUER));
        assertThat(tenant.clientId().orElse(""), is("client-id"));
        assertThat(tenant.endpoints().discoveryUri().orElseThrow(), is(DISCOVERY_URI));
        assertThat(tenant.protectedResource().enabled(), is(true));
        assertThat(tenant.protectedResource().tokenValidation().method().orElseThrow(),
                   is(OidcTokenValidationMethod.JWT));
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
    void jwtValidationRequiresIssuerAndJwksOrDiscovery() {
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
    }

    @Test
    void introspectionRequiresEndpointAndClientAuthentication() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));
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
        assertThat(metadata, containsString("token-validation"));
        assertThat(metadata, containsString("client-credentials-grant-enabled"));
    }

    private static OidcTenantConfig jwtProtectedResourceTenant() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.enabled(true)
                        .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
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
