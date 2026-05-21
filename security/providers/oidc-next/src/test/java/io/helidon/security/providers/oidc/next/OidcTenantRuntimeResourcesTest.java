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
import java.util.Optional;

import io.helidon.security.SecurityEnvironment;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcTenantRuntimeResourcesTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI DISCOVERY_URI = URI.create("https://issuer.example/.well-known/openid-configuration");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI JWK_SET_URI = URI.create("https://issuer.example/jwks");
    private static final URI INTROSPECTION_ENDPOINT_URI = URI.create("https://issuer.example/introspect");
    private static final URI USER_INFO_ENDPOINT_URI = URI.create("https://issuer.example/userinfo");
    private static final URI END_SESSION_ENDPOINT_URI = URI.create("https://issuer.example/logout");
    private static final URI DISCOVERED_AUTHORIZATION_ENDPOINT_URI = URI.create("https://discovered.example/authorize");
    private static final URI DISCOVERED_TOKEN_ENDPOINT_URI = URI.create("https://discovered.example/token");
    private static final URI DISCOVERED_JWK_SET_URI = URI.create("https://discovered.example/jwks");
    private static final URI DISCOVERED_INTROSPECTION_ENDPOINT_URI = URI.create("https://discovered.example/introspect");
    private static final URI DISCOVERED_USER_INFO_ENDPOINT_URI = URI.create("https://discovered.example/userinfo");
    private static final URI DISCOVERED_END_SESSION_ENDPOINT_URI = URI.create("https://discovered.example/logout");
    private static final URI PATH_ISSUER = URI.create("https://issuer.example/tenant-a/");
    private static final URI PATH_ISSUER_DISCOVERY_URI =
            URI.create("https://issuer.example/tenant-a/.well-known/openid-configuration");
    private static final String AUDIENCE = "api://default";

    @Test
    void tenantContextContainsRuntimeResourcesFromStaticProviderMetadata() {
        OidcTenantContext context = tenantContext(OidcTenantConfig.builder()
                                                           .issuer(ISSUER)
                                                           .endpoints(it -> it.discoveryUri(DISCOVERY_URI)
                                                                   .authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                                                                   .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                                                                   .jwksUri(JWK_SET_URI)
                                                                   .introspectionEndpointUri(INTROSPECTION_ENDPOINT_URI)
                                                                   .userInfoEndpointUri(USER_INFO_ENDPOINT_URI)
                                                                   .endSessionEndpointUri(END_SESSION_ENDPOINT_URI))
                                                           .buildPrototype());

        assertThat(context.metadata().issuer(), is(Optional.of(ISSUER)));
        assertThat(context.metadata().discoveryUri(), is(Optional.of(DISCOVERY_URI)));
        assertThat(context.metadata().authorizationEndpointUri(), is(Optional.of(AUTHORIZATION_ENDPOINT_URI)));
        assertThat(context.endpointClient().authorizationEndpointUri(), is(Optional.of(AUTHORIZATION_ENDPOINT_URI)));
        assertThat(context.endpointClient().tokenEndpointUri(), is(Optional.of(TOKEN_ENDPOINT_URI)));
        assertThat(context.endpointClient().introspectionEndpointUri(), is(Optional.of(INTROSPECTION_ENDPOINT_URI)));
        assertThat(context.endpointClient().userInfoEndpointUri(), is(Optional.of(USER_INFO_ENDPOINT_URI)));
        assertThat(context.endpointClient().endSessionEndpointUri(), is(Optional.of(END_SESSION_ENDPOINT_URI)));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.of(JWK_SET_URI)));
        assertThat(context.tokenValidationPolicy().method().isEmpty(), is(true));
        assertThat(context.cookieStateHandler().cookieConfig(), is(context.tenantConfig().cookies()));
    }

    @Test
    void staticProviderMetadataOverridesDiscoveredProviderMetadata() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER),
                                                                          Optional.of(DISCOVERY_URI),
                                                                          Optional.of(AUTHORIZATION_ENDPOINT_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.of(INTROSPECTION_ENDPOINT_URI),
                                                                          Optional.empty(),
                                                                          Optional.of(END_SESSION_ENDPOINT_URI));
        OidcProviderMetadata discoveredMetadata = OidcProviderMetadata.create(Optional.of(ISSUER),
                                                                              Optional.empty(),
                                                                              Optional.of(DISCOVERED_AUTHORIZATION_ENDPOINT_URI),
                                                                              Optional.of(DISCOVERED_TOKEN_ENDPOINT_URI),
                                                                              Optional.of(DISCOVERED_JWK_SET_URI),
                                                                              Optional.of(DISCOVERED_INTROSPECTION_ENDPOINT_URI),
                                                                              Optional.of(DISCOVERED_USER_INFO_ENDPOINT_URI),
                                                                              Optional.of(DISCOVERED_END_SESSION_ENDPOINT_URI));

        OidcProviderMetadata merged = staticMetadata.mergeDiscovered(discoveredMetadata);

        assertThat(merged.issuer(), is(Optional.of(ISSUER)));
        assertThat(merged.discoveryUri(), is(Optional.of(DISCOVERY_URI)));
        assertThat(merged.authorizationEndpointUri(), is(Optional.of(AUTHORIZATION_ENDPOINT_URI)));
        assertThat(merged.tokenEndpointUri(), is(Optional.of(DISCOVERED_TOKEN_ENDPOINT_URI)));
        assertThat(merged.jwkSetUri(), is(Optional.of(DISCOVERED_JWK_SET_URI)));
        assertThat(merged.introspectionEndpointUri(), is(Optional.of(INTROSPECTION_ENDPOINT_URI)));
        assertThat(merged.userInfoEndpointUri(), is(Optional.of(DISCOVERED_USER_INFO_ENDPOINT_URI)));
        assertThat(merged.endSessionEndpointUri(), is(Optional.of(END_SESSION_ENDPOINT_URI)));
    }

    @Test
    void discoveredProviderMetadataIssuerMustMatchStaticIssuer() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER),
                                                                          Optional.of(DISCOVERY_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty());
        OidcProviderMetadata discoveredMetadata = OidcProviderMetadata.create(Optional.of(URI.create("https://other.example")),
                                                                              Optional.empty(),
                                                                              Optional.of(DISCOVERED_AUTHORIZATION_ENDPOINT_URI),
                                                                              Optional.of(DISCOVERED_TOKEN_ENDPOINT_URI),
                                                                              Optional.of(DISCOVERED_JWK_SET_URI),
                                                                              Optional.empty(),
                                                                              Optional.empty(),
                                                                              Optional.empty());

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> staticMetadata.mergeDiscovered(discoveredMetadata));

        assertThat(thrown.getMessage(), is("discovered issuer must match configured issuer"));
    }

    @Test
    void discoveredProviderMetadataIssuerIsRequired() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER),
                                                                          Optional.of(DISCOVERY_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty());
        OidcProviderMetadata discoveredMetadata = OidcProviderMetadata.create(Optional.empty(),
                                                                              Optional.empty(),
                                                                              Optional.of(DISCOVERED_AUTHORIZATION_ENDPOINT_URI),
                                                                              Optional.of(DISCOVERED_TOKEN_ENDPOINT_URI),
                                                                              Optional.of(DISCOVERED_JWK_SET_URI),
                                                                              Optional.empty(),
                                                                              Optional.empty(),
                                                                              Optional.empty());

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> staticMetadata.mergeDiscovered(discoveredMetadata));

        assertThat(thrown.getMessage(), is("discovered issuer must be present"));
    }

    @Test
    void discoveryUriIsRetainedWhenJwkSetUriIsNotStatic() {
        OidcTenantContext context = tenantContext(OidcTenantConfig.builder()
                                                           .issuer(ISSUER)
                                                           .endpoints(it -> it.discoveryUri(DISCOVERY_URI))
                                                           .buildPrototype());

        assertThat(context.state(), is(OidcTenantState.READY));
        assertThat(context.metadata().discoveryUri(), is(Optional.of(DISCOVERY_URI)));
        assertThat(context.metadata().jwkSetUri(), is(Optional.empty()));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.empty()));
        assertThat(context.tokenValidationPolicy().method().isEmpty(), is(true));
    }

    @Test
    void discoveryUriDefaultsFromIssuer() {
        OidcTenantContext context = tenantContext(OidcTenantConfig.builder()
                                                           .issuer(PATH_ISSUER)
                                                           .buildPrototype());

        assertThat(context.metadata().issuer(), is(Optional.of(PATH_ISSUER)));
        assertThat(context.metadata().discoveryUri(), is(Optional.of(PATH_ISSUER_DISCOVERY_URI)));
    }

    private static OidcTenantContext tenantContext(OidcTenantConfig tenantConfig) {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .buildPrototype());
        return registry.tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();
    }
}
