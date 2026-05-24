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

import io.helidon.json.JsonObject;

final class OidcProviderMetadata {
    private final Optional<URI> issuer;
    private final Optional<URI> wellKnownUri;
    private final Optional<URI> authorizationEndpointUri;
    private final Optional<URI> tokenEndpointUri;
    private final Optional<URI> mutualTlsTokenEndpointUri;
    private final Optional<URI> jwkSetUri;
    private final Optional<URI> introspectionEndpointUri;
    private final Optional<URI> userInfoEndpointUri;
    private final Optional<URI> endSessionEndpointUri;

    private OidcProviderMetadata(Optional<URI> issuer,
                                 Optional<URI> wellKnownUri,
                                 Optional<URI> authorizationEndpointUri,
                                 Optional<URI> tokenEndpointUri,
                                 Optional<URI> mutualTlsTokenEndpointUri,
                                 Optional<URI> jwkSetUri,
                                 Optional<URI> introspectionEndpointUri,
                                 Optional<URI> userInfoEndpointUri,
                                 Optional<URI> endSessionEndpointUri) {
        this.issuer = issuer;
        this.wellKnownUri = wellKnownUri;
        this.authorizationEndpointUri = authorizationEndpointUri;
        this.tokenEndpointUri = tokenEndpointUri;
        this.mutualTlsTokenEndpointUri = mutualTlsTokenEndpointUri;
        this.jwkSetUri = jwkSetUri;
        this.introspectionEndpointUri = introspectionEndpointUri;
        this.userInfoEndpointUri = userInfoEndpointUri;
        this.endSessionEndpointUri = endSessionEndpointUri;
    }

    static OidcProviderMetadata fromStaticConfig(OidcTenantConfig tenantConfig) {
        OidcEndpointConfig endpoints = tenantConfig.endpoints();
        return create(tenantConfig.issuer(),
                      wellKnownUri(tenantConfig.issuer(), endpoints),
                      endpoints.authorizationEndpointUri(),
                      endpoints.tokenEndpointUri(),
                      Optional.empty(),
                      endpoints.jwksUri(),
                      endpoints.introspectionEndpointUri(),
                      endpoints.userInfoEndpointUri(),
                      endpoints.endSessionEndpointUri());
    }

    static OidcProviderMetadata create(Optional<URI> issuer,
                                       Optional<URI> wellKnownUri,
                                       Optional<URI> authorizationEndpointUri,
                                       Optional<URI> tokenEndpointUri,
                                       Optional<URI> jwkSetUri,
                                       Optional<URI> introspectionEndpointUri,
                                       Optional<URI> userInfoEndpointUri,
                                       Optional<URI> endSessionEndpointUri) {
        return create(issuer,
                      wellKnownUri,
                      authorizationEndpointUri,
                      tokenEndpointUri,
                      Optional.empty(),
                      jwkSetUri,
                      introspectionEndpointUri,
                      userInfoEndpointUri,
                      endSessionEndpointUri);
    }

    static OidcProviderMetadata create(Optional<URI> issuer,
                                       Optional<URI> wellKnownUri,
                                       Optional<URI> authorizationEndpointUri,
                                       Optional<URI> tokenEndpointUri,
                                       Optional<URI> mutualTlsTokenEndpointUri,
                                       Optional<URI> jwkSetUri,
                                       Optional<URI> introspectionEndpointUri,
                                       Optional<URI> userInfoEndpointUri,
                                       Optional<URI> endSessionEndpointUri) {
        return new OidcProviderMetadata(issuer,
                                        wellKnownUri,
                                        authorizationEndpointUri,
                                        tokenEndpointUri,
                                        mutualTlsTokenEndpointUri,
                                        jwkSetUri,
                                        introspectionEndpointUri,
                                        userInfoEndpointUri,
                                        endSessionEndpointUri);
    }

    static OidcProviderMetadata fromWellKnownMetadataJson(JsonObject json) {
        return create(uriValue(json, "issuer"),
                      Optional.empty(),
                      uriValue(json, "authorization_endpoint"),
                      uriValue(json, "token_endpoint"),
                      mutualTlsTokenEndpointUri(json),
                      uriValue(json, "jwks_uri"),
                      uriValue(json, "introspection_endpoint"),
                      uriValue(json, "userinfo_endpoint"),
                      uriValue(json, "end_session_endpoint"));
    }

    OidcProviderMetadata mergeWellKnownMetadata(OidcProviderMetadata wellKnownMetadata) {
        validateWellKnownMetadataIssuer(wellKnownMetadata);
        return create(issuer.or(wellKnownMetadata::issuer),
                      wellKnownUri.or(wellKnownMetadata::wellKnownUri),
                      authorizationEndpointUri.or(wellKnownMetadata::authorizationEndpointUri),
                      tokenEndpointUri.or(wellKnownMetadata::tokenEndpointUri),
                      mutualTlsTokenEndpointUri.or(() -> tokenEndpointUri.isPresent()
                              ? Optional.empty()
                              : wellKnownMetadata.mutualTlsTokenEndpointUri()),
                      jwkSetUri.or(wellKnownMetadata::jwkSetUri),
                      introspectionEndpointUri.or(wellKnownMetadata::introspectionEndpointUri),
                      userInfoEndpointUri.or(wellKnownMetadata::userInfoEndpointUri),
                      endSessionEndpointUri.or(wellKnownMetadata::endSessionEndpointUri));
    }

    Optional<URI> issuer() {
        return issuer;
    }

    Optional<URI> wellKnownUri() {
        return wellKnownUri;
    }

    Optional<URI> authorizationEndpointUri() {
        return authorizationEndpointUri;
    }

    Optional<URI> tokenEndpointUri() {
        return tokenEndpointUri;
    }

    Optional<URI> mutualTlsTokenEndpointUri() {
        return mutualTlsTokenEndpointUri;
    }

    Optional<URI> jwkSetUri() {
        return jwkSetUri;
    }

    Optional<URI> introspectionEndpointUri() {
        return introspectionEndpointUri;
    }

    Optional<URI> userInfoEndpointUri() {
        return userInfoEndpointUri;
    }

    Optional<URI> endSessionEndpointUri() {
        return endSessionEndpointUri;
    }

    static Optional<URI> wellKnownUri(Optional<URI> issuer, OidcEndpointConfig endpoints) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 4 Obtaining OpenID Provider Configuration Information
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
         * Quotes: "concatenating the string `/.well-known/openid-configuration` to the Issuer";
         * "any terminating `/` MUST be removed before appending".
         */
        Optional<URI> configuredWellKnownUri = endpoints.wellKnownUri();
        if (configuredWellKnownUri.isPresent()) {
            return configuredWellKnownUri;
        }
        if (issuer.isEmpty()) {
            return Optional.empty();
        }
        String issuerValue = issuer.orElseThrow().toString();
        while (issuerValue.endsWith("/")) {
            issuerValue = issuerValue.substring(0, issuerValue.length() - 1);
        }
        return Optional.of(URI.create(issuerValue + "/.well-known/openid-configuration"));
    }

    private static Optional<URI> uriValue(JsonObject json, String name) {
        return json.stringValue(name)
                .map(URI::create);
    }

    private static Optional<URI> mutualTlsTokenEndpointUri(JsonObject json) {
        /*
         * Spec: RFC 8705, 5 Metadata for Mutual TLS Endpoint Aliases
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-5
         * Quotes: "`mtls_endpoint_aliases`"; "`token_endpoint`".
         */
        return json.objectValue("mtls_endpoint_aliases")
                .flatMap(aliases -> uriValue(aliases, "token_endpoint"));
    }

    private void validateWellKnownMetadataIssuer(OidcProviderMetadata wellKnownMetadata) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 4.3 OpenID Provider Configuration Validation
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
         * Quotes: "`issuer` REQUIRED"; "Issuer value returned MUST be identical to the Issuer URL".
         */
        URI wellKnownMetadataIssuer = wellKnownMetadata.issuer()
                .orElseThrow(() -> new IllegalArgumentException("well-known metadata issuer must be present"));
        issuer.filter(configuredIssuer -> !configuredIssuer.equals(wellKnownMetadataIssuer))
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException("well-known metadata issuer must match configured issuer");
                });
    }
}
