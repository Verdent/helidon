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
import io.helidon.json.JsonString;
import io.helidon.json.JsonValue;

final class OidcProviderMetadata {
    private final Optional<String> issuer;
    private final Optional<URI> wellKnownUri;
    private final Optional<URI> authorizationEndpointUri;
    private final Optional<URI> tokenEndpointUri;
    private final Optional<URI> mutualTlsTokenEndpointUri;
    private final Optional<URI> jwkSetUri;
    private final Optional<List<String>> responseTypesSupported;
    private final Optional<List<String>> grantTypesSupported;
    private final Optional<List<String>> codeChallengeMethodsSupported;
    private final Optional<List<String>> tokenEndpointAuthenticationMethodsSupported;
    private final Optional<List<String>> tokenEndpointAuthenticationSigningAlgorithmsSupported;
    private final Optional<List<String>> idTokenSigningAlgorithmsSupported;
    private final Optional<List<String>> idTokenEncryptionAlgorithmsSupported;
    private final Optional<List<String>> idTokenContentEncryptionAlgorithmsSupported;
    private final Optional<URI> introspectionEndpointUri;
    private final Optional<List<String>> introspectionEndpointAuthenticationMethodsSupported;
    private final Optional<List<String>> introspectionEndpointAuthenticationSigningAlgorithmsSupported;
    private final Optional<URI> userInfoEndpointUri;
    private final Optional<URI> endSessionEndpointUri;
    private final boolean authorizationResponseIssuerParameterSupported;

    private OidcProviderMetadata(Optional<String> issuer,
                                 Optional<URI> wellKnownUri,
                                 Optional<URI> authorizationEndpointUri,
                                 Optional<URI> tokenEndpointUri,
                                 Optional<URI> mutualTlsTokenEndpointUri,
                                 Optional<URI> jwkSetUri,
                                 Optional<List<String>> responseTypesSupported,
                                 Optional<List<String>> grantTypesSupported,
                                 Optional<List<String>> codeChallengeMethodsSupported,
                                 Optional<List<String>> tokenEndpointAuthenticationMethodsSupported,
                                 Optional<List<String>> tokenEndpointAuthenticationSigningAlgorithmsSupported,
                                 Optional<List<String>> idTokenSigningAlgorithmsSupported,
                                 Optional<List<String>> idTokenEncryptionAlgorithmsSupported,
                                 Optional<List<String>> idTokenContentEncryptionAlgorithmsSupported,
                                 Optional<URI> introspectionEndpointUri,
                                 Optional<List<String>> introspectionEndpointAuthenticationMethodsSupported,
                                 Optional<List<String>> introspectionEndpointAuthenticationSigningAlgorithmsSupported,
                                 Optional<URI> userInfoEndpointUri,
                                 Optional<URI> endSessionEndpointUri,
                                 boolean authorizationResponseIssuerParameterSupported) {
        this.issuer = issuer;
        this.wellKnownUri = wellKnownUri;
        this.authorizationEndpointUri = authorizationEndpointUri;
        this.tokenEndpointUri = tokenEndpointUri;
        this.mutualTlsTokenEndpointUri = mutualTlsTokenEndpointUri;
        this.jwkSetUri = jwkSetUri;
        this.responseTypesSupported = responseTypesSupported.map(List::copyOf);
        this.grantTypesSupported = grantTypesSupported.map(List::copyOf);
        this.codeChallengeMethodsSupported = codeChallengeMethodsSupported.map(List::copyOf);
        this.tokenEndpointAuthenticationMethodsSupported = tokenEndpointAuthenticationMethodsSupported.map(List::copyOf);
        this.tokenEndpointAuthenticationSigningAlgorithmsSupported =
                tokenEndpointAuthenticationSigningAlgorithmsSupported.map(List::copyOf);
        this.idTokenSigningAlgorithmsSupported = idTokenSigningAlgorithmsSupported.map(List::copyOf);
        this.idTokenEncryptionAlgorithmsSupported = idTokenEncryptionAlgorithmsSupported.map(List::copyOf);
        this.idTokenContentEncryptionAlgorithmsSupported = idTokenContentEncryptionAlgorithmsSupported.map(List::copyOf);
        this.introspectionEndpointUri = introspectionEndpointUri;
        this.introspectionEndpointAuthenticationMethodsSupported =
                introspectionEndpointAuthenticationMethodsSupported.map(List::copyOf);
        this.introspectionEndpointAuthenticationSigningAlgorithmsSupported =
                introspectionEndpointAuthenticationSigningAlgorithmsSupported.map(List::copyOf);
        this.userInfoEndpointUri = userInfoEndpointUri;
        this.endSessionEndpointUri = endSessionEndpointUri;
        this.authorizationResponseIssuerParameterSupported = authorizationResponseIssuerParameterSupported;
    }

    static OidcProviderMetadata fromStaticConfig(OidcTenantConfig tenantConfig) {
        OidcEndpointConfig endpoints = tenantConfig.endpoints();
        return create(tenantConfig.issuer(),
                      wellKnownUri(tenantConfig.issuer(), endpoints),
                      endpoints.authorizationEndpointUri(),
                      endpoints.tokenEndpointUri(),
                      Optional.empty(),
                      endpoints.jwksUri(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      endpoints.introspectionEndpointUri(),
                      Optional.empty(),
                      Optional.empty(),
                      endpoints.userInfoEndpointUri(),
                      endpoints.endSessionEndpointUri(),
                      false);
    }

    static OidcProviderMetadata create(Optional<String> issuer,
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
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      introspectionEndpointUri,
                      Optional.empty(),
                      Optional.empty(),
                      userInfoEndpointUri,
                      endSessionEndpointUri,
                      false);
    }

    static OidcProviderMetadata create(Optional<String> issuer,
                                       Optional<URI> wellKnownUri,
                                       Optional<URI> authorizationEndpointUri,
                                       Optional<URI> tokenEndpointUri,
                                       Optional<URI> mutualTlsTokenEndpointUri,
                                       Optional<URI> jwkSetUri,
                                       Optional<URI> introspectionEndpointUri,
                                       Optional<URI> userInfoEndpointUri,
                                       Optional<URI> endSessionEndpointUri,
                                       boolean authorizationResponseIssuerParameterSupported) {
        return create(issuer,
                      wellKnownUri,
                      authorizationEndpointUri,
                      tokenEndpointUri,
                      mutualTlsTokenEndpointUri,
                      jwkSetUri,
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      Optional.empty(),
                      introspectionEndpointUri,
                      Optional.empty(),
                      Optional.empty(),
                      userInfoEndpointUri,
                      endSessionEndpointUri,
                      authorizationResponseIssuerParameterSupported);
    }

    static OidcProviderMetadata create(Optional<String> issuer,
                                       Optional<URI> wellKnownUri,
                                       Optional<URI> authorizationEndpointUri,
                                       Optional<URI> tokenEndpointUri,
                                       Optional<URI> mutualTlsTokenEndpointUri,
                                       Optional<URI> jwkSetUri,
                                       Optional<List<String>> responseTypesSupported,
                                       Optional<List<String>> grantTypesSupported,
                                       Optional<List<String>> codeChallengeMethodsSupported,
                                       Optional<List<String>> tokenEndpointAuthenticationMethodsSupported,
                                       Optional<List<String>> tokenEndpointAuthenticationSigningAlgorithmsSupported,
                                       Optional<List<String>> idTokenSigningAlgorithmsSupported,
                                       Optional<List<String>> idTokenEncryptionAlgorithmsSupported,
                                       Optional<List<String>> idTokenContentEncryptionAlgorithmsSupported,
                                       Optional<URI> introspectionEndpointUri,
                                       Optional<List<String>> introspectionEndpointAuthenticationMethodsSupported,
                                       Optional<List<String>> introspectionEndpointAuthenticationSigningAlgorithmsSupported,
                                       Optional<URI> userInfoEndpointUri,
                                       Optional<URI> endSessionEndpointUri,
                                       boolean authorizationResponseIssuerParameterSupported) {
        return new OidcProviderMetadata(issuer,
                                        wellKnownUri,
                                        authorizationEndpointUri,
                                        tokenEndpointUri,
                                        mutualTlsTokenEndpointUri,
                                        jwkSetUri,
                                        responseTypesSupported,
                                        grantTypesSupported,
                                        codeChallengeMethodsSupported,
                                        tokenEndpointAuthenticationMethodsSupported,
                                        tokenEndpointAuthenticationSigningAlgorithmsSupported,
                                        idTokenSigningAlgorithmsSupported,
                                        idTokenEncryptionAlgorithmsSupported,
                                        idTokenContentEncryptionAlgorithmsSupported,
                                        introspectionEndpointUri,
                                        introspectionEndpointAuthenticationMethodsSupported,
                                        introspectionEndpointAuthenticationSigningAlgorithmsSupported,
                                        userInfoEndpointUri,
                                        endSessionEndpointUri,
                                        authorizationResponseIssuerParameterSupported);
    }

    static OidcProviderMetadata fromWellKnownMetadataJson(JsonObject json) {
        return create(json.stringValue("issuer"),
                      Optional.empty(),
                      uriValue(json, "authorization_endpoint"),
                      uriValue(json, "token_endpoint"),
                      mutualTlsTokenEndpointUri(json),
                      uriValue(json, "jwks_uri"),
                      stringArrayValue(json, "response_types_supported"),
                      stringArrayValue(json, "grant_types_supported"),
                      stringArrayValue(json, "code_challenge_methods_supported"),
                      stringArrayValue(json, "token_endpoint_auth_methods_supported"),
                      stringArrayValue(json, "token_endpoint_auth_signing_alg_values_supported"),
                      stringArrayValue(json, "id_token_signing_alg_values_supported"),
                      stringArrayValue(json, "id_token_encryption_alg_values_supported"),
                      stringArrayValue(json, "id_token_encryption_enc_values_supported"),
                      uriValue(json, "introspection_endpoint"),
                      stringArrayValue(json, "introspection_endpoint_auth_methods_supported"),
                      stringArrayValue(json, "introspection_endpoint_auth_signing_alg_values_supported"),
                      uriValue(json, "userinfo_endpoint"),
                      uriValue(json, "end_session_endpoint"),
                      json.booleanValue("authorization_response_iss_parameter_supported")
                              .orElse(false));
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
                      responseTypesSupported.or(wellKnownMetadata::responseTypesSupported),
                      grantTypesSupported.or(wellKnownMetadata::grantTypesSupported),
                      codeChallengeMethodsSupported.or(wellKnownMetadata::codeChallengeMethodsSupported),
                      tokenEndpointAuthenticationMethodsSupported
                              .or(wellKnownMetadata::tokenEndpointAuthenticationMethodsSupported),
                      tokenEndpointAuthenticationSigningAlgorithmsSupported
                              .or(wellKnownMetadata::tokenEndpointAuthenticationSigningAlgorithmsSupported),
                      idTokenSigningAlgorithmsSupported.or(wellKnownMetadata::idTokenSigningAlgorithmsSupported),
                      idTokenEncryptionAlgorithmsSupported.or(wellKnownMetadata::idTokenEncryptionAlgorithmsSupported),
                      idTokenContentEncryptionAlgorithmsSupported
                              .or(wellKnownMetadata::idTokenContentEncryptionAlgorithmsSupported),
                      introspectionEndpointUri.or(wellKnownMetadata::introspectionEndpointUri),
                      introspectionEndpointAuthenticationMethodsSupported
                              .or(wellKnownMetadata::introspectionEndpointAuthenticationMethodsSupported),
                      introspectionEndpointAuthenticationSigningAlgorithmsSupported
                              .or(wellKnownMetadata::introspectionEndpointAuthenticationSigningAlgorithmsSupported),
                      userInfoEndpointUri.or(wellKnownMetadata::userInfoEndpointUri),
                      endSessionEndpointUri.or(wellKnownMetadata::endSessionEndpointUri),
                      authorizationResponseIssuerParameterSupported
                              || wellKnownMetadata.authorizationResponseIssuerParameterSupported());
    }

    Optional<String> issuer() {
        return issuer;
    }

    Optional<URI> issuerUri() {
        return issuer.map(URI::create);
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

    Optional<List<String>> responseTypesSupported() {
        return responseTypesSupported;
    }

    Optional<List<String>> grantTypesSupported() {
        return grantTypesSupported;
    }

    Optional<List<String>> codeChallengeMethodsSupported() {
        return codeChallengeMethodsSupported;
    }

    Optional<List<String>> tokenEndpointAuthenticationMethodsSupported() {
        return tokenEndpointAuthenticationMethodsSupported;
    }

    Optional<List<String>> tokenEndpointAuthenticationSigningAlgorithmsSupported() {
        return tokenEndpointAuthenticationSigningAlgorithmsSupported;
    }

    Optional<List<String>> idTokenSigningAlgorithmsSupported() {
        return idTokenSigningAlgorithmsSupported;
    }

    Optional<List<String>> idTokenEncryptionAlgorithmsSupported() {
        return idTokenEncryptionAlgorithmsSupported;
    }

    Optional<List<String>> idTokenContentEncryptionAlgorithmsSupported() {
        return idTokenContentEncryptionAlgorithmsSupported;
    }

    Optional<URI> introspectionEndpointUri() {
        return introspectionEndpointUri;
    }

    Optional<List<String>> introspectionEndpointAuthenticationMethodsSupported() {
        return introspectionEndpointAuthenticationMethodsSupported;
    }

    Optional<List<String>> introspectionEndpointAuthenticationSigningAlgorithmsSupported() {
        return introspectionEndpointAuthenticationSigningAlgorithmsSupported;
    }

    Optional<URI> userInfoEndpointUri() {
        return userInfoEndpointUri;
    }

    Optional<URI> endSessionEndpointUri() {
        return endSessionEndpointUri;
    }

    boolean authorizationResponseIssuerParameterSupported() {
        return authorizationResponseIssuerParameterSupported;
    }

    static Optional<URI> wellKnownUri(Optional<String> issuer, OidcEndpointConfig endpoints) {
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
        String issuerValue = issuer.orElseThrow();
        while (issuerValue.endsWith("/")) {
            issuerValue = issuerValue.substring(0, issuerValue.length() - 1);
        }
        return Optional.of(URI.create(issuerValue + "/.well-known/openid-configuration"));
    }

    private static Optional<URI> uriValue(JsonObject json, String name) {
        return json.stringValue(name)
                .map(URI::create);
    }

    private static Optional<List<String>> stringArrayValue(JsonObject json, String name) {
        return json.arrayValue(name)
                .map(array -> array.values()
                        .stream()
                        .map(JsonValue::asString)
                        .map(JsonString::value)
                        .toList());
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
         *
         * Spec: OpenID Connect Discovery 1.0, 5 String Operations
         * https://openid.net/specs/openid-connect-discovery-1_0.html#StringOps
         * Quote: "Unicode code point to code point equality comparison".
         */
        String wellKnownMetadataIssuer = wellKnownMetadata.issuer()
                .orElseThrow(() -> new IllegalArgumentException("well-known metadata issuer must be present"));
        issuer.filter(configuredIssuer -> !configuredIssuer.equals(wellKnownMetadataIssuer))
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException("well-known metadata issuer must match configured issuer");
                });
    }
}
