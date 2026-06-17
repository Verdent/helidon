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
import java.util.List;
import java.util.Optional;

import io.helidon.json.JsonObject;
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
                                                           .issuer(ISSUER.toString())
                                                           .endpoints(it -> it.wellKnownUri(WELL_KNOWN_URI)
                                                                   .authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                                                                   .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                                                                   .jwksUri(JWK_SET_URI)
                                                                   .introspectionEndpointUri(INTROSPECTION_ENDPOINT_URI)
                                                                   .userInfoEndpointUri(USER_INFO_ENDPOINT_URI)
                                                                   .endSessionEndpointUri(END_SESSION_ENDPOINT_URI))
                                                           .buildPrototype());

        assertThat(context.metadata().issuer(), is(Optional.of(ISSUER.toString())));
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
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER.toString()),
                                                                          Optional.of(WELL_KNOWN_URI),
                                                                          Optional.of(AUTHORIZATION_ENDPOINT_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.of(INTROSPECTION_ENDPOINT_URI),
                                                                          Optional.of(USER_INFO_ENDPOINT_URI),
                                                                          Optional.of(END_SESSION_ENDPOINT_URI));
        OidcProviderMetadata wellKnownMetadata =
                OidcProviderMetadata.create(Optional.of(ISSUER.toString()),
                                            Optional.empty(),
                                            Optional.of(WELL_KNOWN_METADATA_AUTHORIZATION_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_TOKEN_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_JWK_SET_URI),
                                            Optional.of(WELL_KNOWN_METADATA_INTROSPECTION_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_USER_INFO_ENDPOINT_URI),
                                            Optional.of(WELL_KNOWN_METADATA_END_SESSION_ENDPOINT_URI));

        OidcProviderMetadata merged = staticMetadata.mergeWellKnownMetadata(wellKnownMetadata);

        assertThat(merged.issuer(), is(Optional.of(ISSUER.toString())));
        assertThat(merged.wellKnownUri(), is(Optional.of(WELL_KNOWN_URI)));
        assertThat(merged.authorizationEndpointUri(), is(Optional.of(AUTHORIZATION_ENDPOINT_URI)));
        assertThat(merged.tokenEndpointUri(), is(Optional.of(WELL_KNOWN_METADATA_TOKEN_ENDPOINT_URI)));
        assertThat(merged.jwkSetUri(), is(Optional.of(WELL_KNOWN_METADATA_JWK_SET_URI)));
        assertThat(merged.introspectionEndpointUri(), is(Optional.of(INTROSPECTION_ENDPOINT_URI)));
        assertThat(merged.userInfoEndpointUri(), is(Optional.of(USER_INFO_ENDPOINT_URI)));
        assertThat(merged.endSessionEndpointUri(), is(Optional.of(END_SESSION_ENDPOINT_URI)));
    }

    @Test
    void jwkSetUriTracksWellKnownMetadataSource() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER.toString()),
                                                                          Optional.of(WELL_KNOWN_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty());
        OidcProviderMetadata wellKnownMetadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("jwks_uri", WELL_KNOWN_METADATA_JWK_SET_URI.toString())
                .build());

        OidcProviderMetadata merged = staticMetadata.mergeWellKnownMetadata(wellKnownMetadata);

        assertThat(merged.jwkSetUri(), is(Optional.of(WELL_KNOWN_METADATA_JWK_SET_URI)));
        assertThat(merged.jwkSetUriFromWellKnownMetadata(), is(true));

        OidcProviderMetadata staticMetadataWithJwkSet = OidcProviderMetadata.create(Optional.of(ISSUER.toString()),
                                                                                    Optional.of(WELL_KNOWN_URI),
                                                                                    Optional.empty(),
                                                                                    Optional.empty(),
                                                                                    Optional.of(JWK_SET_URI),
                                                                                    Optional.empty(),
                                                                                    Optional.empty(),
                                                                                    Optional.empty());

        OidcProviderMetadata mergedWithStaticJwkSet = staticMetadataWithJwkSet.mergeWellKnownMetadata(wellKnownMetadata);

        assertThat(mergedWithStaticJwkSet.jwkSetUri(), is(Optional.of(JWK_SET_URI)));
        assertThat(mergedWithStaticJwkSet.jwkSetUriFromWellKnownMetadata(), is(false));
    }

    @Test
    void wellKnownMetadataIssuerMustMatchStaticIssuer() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER.toString()),
                                                                          Optional.of(WELL_KNOWN_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty());
        OidcProviderMetadata wellKnownMetadata =
                OidcProviderMetadata.create(Optional.of("https://other.example"),
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
    void wellKnownMetadataIssuerMustMatchStaticIssuerExactly() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER.toString()),
                                                                          Optional.of(WELL_KNOWN_URI),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty(),
                                                                          Optional.empty());
        OidcProviderMetadata wellKnownMetadata =
                OidcProviderMetadata.create(Optional.of("https://ISSUER.example"),
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
    void wellKnownMetadataParsesAuthorizationResponseIssuerSupport() {
        OidcProviderMetadata metadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("authorization_response_iss_parameter_supported", true)
                .build());

        assertThat(metadata.authorizationResponseIssuerParameterSupported(), is(true));
        assertThat(metadata.tlsClientCertificateBoundAccessTokens(), is(false));
    }

    @Test
    void wellKnownMetadataParsesCertificateBoundAccessTokenSupport() {
        OidcProviderMetadata metadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("tls_client_certificate_bound_access_tokens", true)
                .build());

        assertThat(metadata.tlsClientCertificateBoundAccessTokens(), is(true));
    }

    @Test
    void wellKnownMetadataParsesPushedAuthorizationRequestSupport() {
        URI endpoint = URI.create("https://issuer.example/par");
        OidcProviderMetadata metadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("pushed_authorization_request_endpoint", endpoint.toString())
                .set("require_pushed_authorization_requests", true)
                .build());

        assertThat(metadata.pushedAuthorizationRequestEndpointUri(), is(Optional.of(endpoint)));
        assertThat(metadata.requirePushedAuthorizationRequests(), is(true));
    }

    @Test
    void wellKnownMetadataParsesFlowAndTokenEndpointCapabilities() {
        OidcProviderMetadata metadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code", "client_credentials"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                .setStrings("token_endpoint_auth_signing_alg_values_supported", List.of("RS256"))
                .build());

        assertThat(metadata.responseTypesSupported().orElseThrow(), is(List.of("code")));
        assertThat(metadata.grantTypesSupported().orElseThrow(),
                   is(List.of("authorization_code", "client_credentials")));
        assertThat(metadata.codeChallengeMethodsSupported().orElseThrow(), is(List.of("S256")));
        assertThat(metadata.tokenEndpointAuthenticationMethodsSupported().orElseThrow(),
                   is(List.of("client_secret_basic")));
        assertThat(metadata.tokenEndpointAuthenticationSigningAlgorithmsSupported().orElseThrow(), is(List.of("RS256")));
    }

    @Test
    void wellKnownMetadataParsesIdTokenEncryptionAlgorithms() {
        OidcProviderMetadata metadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .setStrings("id_token_encryption_alg_values_supported", List.of("RSA-OAEP-256"))
                .setStrings("id_token_encryption_enc_values_supported", List.of("A256GCM"))
                .build());

        assertThat(metadata.idTokenEncryptionAlgorithmsSupported().orElseThrow(), is(List.of("RSA-OAEP-256")));
        assertThat(metadata.idTokenContentEncryptionAlgorithmsSupported().orElseThrow(), is(List.of("A256GCM")));
    }

    @Test
    void wellKnownMetadataIssuerIsRequired() {
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.create(Optional.of(ISSUER.toString()),
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
                                                           .issuer(ISSUER.toString())
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
                                                           .issuer(PATH_ISSUER.toString())
                                                           .buildPrototype());

        assertThat(context.metadata().issuer(), is(Optional.of(PATH_ISSUER.toString())));
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
