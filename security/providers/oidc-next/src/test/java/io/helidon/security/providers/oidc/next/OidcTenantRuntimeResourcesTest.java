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
    private static final URI WELL_KNOWN_URI = URI.create("https://issuer.example/.well-known/openid-configuration");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI JWK_SET_URI = URI.create("https://issuer.example/jwks");
    private static final URI INTROSPECTION_ENDPOINT_URI = URI.create("https://issuer.example/introspect");
    private static final URI USER_INFO_ENDPOINT_URI = URI.create("https://issuer.example/userinfo");
    private static final URI END_SESSION_ENDPOINT_URI = URI.create("https://issuer.example/logout");
    private static final URI WELL_KNOWN_METADATA_AUTHORIZATION_ENDPOINT_URI =
            URI.create("https://metadata.example/authorize");
    private static final URI WELL_KNOWN_METADATA_TOKEN_ENDPOINT_URI = URI.create("https://metadata.example/token");
    private static final URI WELL_KNOWN_METADATA_JWK_SET_URI = URI.create("https://metadata.example/jwks");
    private static final URI WELL_KNOWN_METADATA_INTROSPECTION_ENDPOINT_URI =
            URI.create("https://metadata.example/introspect");
    private static final URI WELL_KNOWN_METADATA_USER_INFO_ENDPOINT_URI = URI.create("https://metadata.example/userinfo");
    private static final URI WELL_KNOWN_METADATA_END_SESSION_ENDPOINT_URI = URI.create("https://metadata.example/logout");
    private static final URI PATH_ISSUER = URI.create("https://issuer.example/tenant-a/");
    private static final URI PATH_ISSUER_WELL_KNOWN_URI =
            URI.create("https://issuer.example/tenant-a/.well-known/openid-configuration");
    private static final String AUDIENCE = "api://default";

    @Test
    void tenantContextContainsRuntimeResourcesFromStaticProviderMetadata() {
        OidcTenantContext context = tenantContext(OidcTenantConfig.builder()
                                                           .issuer(ISSUER)
                                                           .endpoints(it -> it.wellKnownUri(WELL_KNOWN_URI)
                                                                   .authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                                                                   .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                                                                   .jwksUri(JWK_SET_URI)
                                                                   .introspectionEndpointUri(INTROSPECTION_ENDPOINT_URI)
                                                                   .userInfoEndpointUri(USER_INFO_ENDPOINT_URI)
                                                                   .endSessionEndpointUri(END_SESSION_ENDPOINT_URI))
                                                           .buildPrototype());

        assertThat(context.metadata().issuer(), is(Optional.of(ISSUER)));
        assertThat(context.metadata().wellKnownUri(), is(Optional.of(WELL_KNOWN_URI)));
        assertThat(context.metadata().authorizationEndpointUri(), is(Optional.of(AUTHORIZATION_ENDPOINT_URI)));
        assertThat(context.metadata().tokenEndpointUri(), is(Optional.of(TOKEN_ENDPOINT_URI)));
        assertThat(context.metadata().introspectionEndpointUri(), is(Optional.of(INTROSPECTION_ENDPOINT_URI)));
        assertThat(context.metadata().userInfoEndpointUri(), is(Optional.of(USER_INFO_ENDPOINT_URI)));
        assertThat(context.metadata().endSessionEndpointUri(), is(Optional.of(END_SESSION_ENDPOINT_URI)));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.of(JWK_SET_URI)));
        assertThat(context.tokenValidation().method().isEmpty(), is(true));
        assertThat(context.cookieStateHandler().cookieConfig(), is(context.tenantConfig().cookies()));
    }

    @Test
    void staticProviderMetadataOverridesWellKnownMetadata() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER),
                                                                          Optional.of(WELL_KNOWN_URI),
                                                                          Optional.of(AUTHORIZATION_ENDPOINT_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.of(INTROSPECTION_ENDPOINT_URI),
                                                                          Optional.of(USER_INFO_ENDPOINT_URI),
                                                                          Optional.of(END_SESSION_ENDPOINT_URI));
        OidcProviderMetadata wellKnownMetadata =
                OidcProviderMetadata.create(Optional.of(ISSUER),
                                            Optional.empty(),
                                            Optional.of(WELL_KNOWN_METADATA_AUTHORIZATION_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_TOKEN_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_JWK_SET_URI),
                                            Optional.of(WELL_KNOWN_METADATA_INTROSPECTION_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_USER_INFO_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_END_SESSION_ENDPOINT_URI));

        OidcProviderMetadata merged = staticMetadata.mergeWellKnownMetadata(wellKnownMetadata);

        assertThat(merged.issuer(), is(Optional.of(ISSUER)));
        assertThat(merged.wellKnownUri(), is(Optional.of(WELL_KNOWN_URI)));
        assertThat(merged.authorizationEndpointUri(), is(Optional.of(AUTHORIZATION_ENDPOINT_URI)));
        assertThat(merged.tokenEndpointUri(), is(Optional.of(WELL_KNOWN_METADATA_TOKEN_ENDPOINT_URI)));
        assertThat(merged.jwkSetUri(), is(Optional.of(WELL_KNOWN_METADATA_JWK_SET_URI)));
        assertThat(merged.introspectionEndpointUri(), is(Optional.of(INTROSPECTION_ENDPOINT_URI)));
        assertThat(merged.userInfoEndpointUri(), is(Optional.of(USER_INFO_ENDPOINT_URI)));
        assertThat(merged.endSessionEndpointUri(), is(Optional.of(END_SESSION_ENDPOINT_URI)));
    }

    @Test
    void wellKnownMetadataIssuerMustMatchStaticIssuer() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER),
                                                                          Optional.of(WELL_KNOWN_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty());
        OidcProviderMetadata wellKnownMetadata =
                OidcProviderMetadata.create(Optional.of(URI.create("https://other.example")),
                                            Optional.empty(),
                                            Optional.of(WELL_KNOWN_METADATA_AUTHORIZATION_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_TOKEN_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_JWK_SET_URI),
                                            Optional.empty(),
                                            Optional.empty(),
                                            Optional.empty());

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> staticMetadata.mergeWellKnownMetadata(wellKnownMetadata));

        assertThat(thrown.getMessage(), is("well-known metadata issuer must match configured issuer"));
    }

    @Test
    void wellKnownMetadataIssuerIsRequired() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER),
                                                                          Optional.of(WELL_KNOWN_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty());
        OidcProviderMetadata wellKnownMetadata =
                OidcProviderMetadata.create(Optional.empty(),
                                            Optional.empty(),
                                            Optional.of(WELL_KNOWN_METADATA_AUTHORIZATION_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_TOKEN_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_JWK_SET_URI),
                                            Optional.empty(),
                                            Optional.empty(),
                                            Optional.empty());

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> staticMetadata.mergeWellKnownMetadata(wellKnownMetadata));

        assertThat(thrown.getMessage(), is("well-known metadata issuer must be present"));
    }

    @Test
    void wellKnownUriIsRetainedWhenJwkSetUriIsNotStatic() {
        OidcTenantContext context = tenantContext(OidcTenantConfig.builder()
                                                           .issuer(ISSUER)
                                                           .endpoints(it -> it.wellKnownUri(WELL_KNOWN_URI))
                                                           .buildPrototype());

        assertThat(context.state(), is(OidcTenantState.READY));
        assertThat(context.metadata().wellKnownUri(), is(Optional.of(WELL_KNOWN_URI)));
        assertThat(context.metadata().jwkSetUri(), is(Optional.empty()));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.empty()));
        assertThat(context.tokenValidation().method().isEmpty(), is(true));
    }

    @Test
    void wellKnownUriDefaultsFromIssuer() {
        OidcTenantContext context = tenantContext(OidcTenantConfig.builder()
                                                           .issuer(PATH_ISSUER)
                                                           .buildPrototype());

        assertThat(context.metadata().issuer(), is(Optional.of(PATH_ISSUER)));
        assertThat(context.metadata().wellKnownUri(), is(Optional.of(PATH_ISSUER_WELL_KNOWN_URI)));
    }

    private static OidcTenantContext tenantContext(OidcTenantConfig tenantConfig) {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .buildPrototype());
        return registry.tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();
    }
}
