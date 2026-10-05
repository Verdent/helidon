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
    private final Optional<URI> mutualTlsPushedAuthorizationRequestEndpointUri;
    private final Optional<URI> mutualTlsIntrospectionEndpointUri;
    private final Optional<URI> mutualTlsUserInfoEndpointUri;
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
    private final Optional<List<String>> userInfoSigningAlgorithmsSupported;
    private final Optional<List<String>> userInfoEncryptionAlgorithmsSupported;
    private final Optional<List<String>> userInfoContentEncryptionAlgorithmsSupported;
    private final Optional<URI> endSessionEndpointUri;
    private final Optional<URI> pushedAuthorizationRequestEndpointUri;
    private final boolean authorizationResponseIssuerParameterSupported;
    private final boolean tlsClientCertificateBoundAccessTokens;
    private final boolean requirePushedAuthorizationRequests;
    private final Optional<Boolean> requestParameterSupported;
    private final Optional<List<String>> requestObjectSigningAlgorithmsSupported;
    private final Optional<List<String>> requestObjectEncryptionAlgorithmsSupported;
    private final Optional<List<String>> requestObjectContentEncryptionAlgorithmsSupported;
    private final boolean requireSignedRequestObject;
    private final boolean wellKnownMetadataLoaded;

    private OidcProviderMetadata(MetadataValues values) {
        this.issuer = values.issuer;
        this.wellKnownUri = values.wellKnownUri;
        this.authorizationEndpointUri = values.authorizationEndpointUri;
        this.tokenEndpointUri = values.tokenEndpointUri;
        this.mutualTlsTokenEndpointUri = values.mutualTlsTokenEndpointUri;
        this.mutualTlsPushedAuthorizationRequestEndpointUri = values.mutualTlsPushedAuthorizationRequestEndpointUri;
        this.mutualTlsIntrospectionEndpointUri = values.mutualTlsIntrospectionEndpointUri;
        this.mutualTlsUserInfoEndpointUri = values.mutualTlsUserInfoEndpointUri;
        this.jwkSetUri = values.jwkSetUri;
        this.responseTypesSupported = values.responseTypesSupported.map(List::copyOf);
        this.grantTypesSupported = values.grantTypesSupported.map(List::copyOf);
        this.codeChallengeMethodsSupported = values.codeChallengeMethodsSupported.map(List::copyOf);
        this.tokenEndpointAuthenticationMethodsSupported = values.tokenEndpointAuthenticationMethodsSupported.map(List::copyOf);
        this.tokenEndpointAuthenticationSigningAlgorithmsSupported =
                values.tokenEndpointAuthenticationSigningAlgorithmsSupported.map(List::copyOf);
        this.idTokenSigningAlgorithmsSupported = values.idTokenSigningAlgorithmsSupported.map(List::copyOf);
        this.idTokenEncryptionAlgorithmsSupported = values.idTokenEncryptionAlgorithmsSupported.map(List::copyOf);
        this.idTokenContentEncryptionAlgorithmsSupported = values.idTokenContentEncryptionAlgorithmsSupported.map(List::copyOf);
        this.introspectionEndpointUri = values.introspectionEndpointUri;
        this.introspectionEndpointAuthenticationMethodsSupported =
                values.introspectionEndpointAuthenticationMethodsSupported.map(List::copyOf);
        this.introspectionEndpointAuthenticationSigningAlgorithmsSupported =
                values.introspectionEndpointAuthenticationSigningAlgorithmsSupported.map(List::copyOf);
        this.userInfoEndpointUri = values.userInfoEndpointUri;
        this.userInfoSigningAlgorithmsSupported = values.userInfoSigningAlgorithmsSupported.map(List::copyOf);
        this.userInfoEncryptionAlgorithmsSupported = values.userInfoEncryptionAlgorithmsSupported.map(List::copyOf);
        this.userInfoContentEncryptionAlgorithmsSupported =
                values.userInfoContentEncryptionAlgorithmsSupported.map(List::copyOf);
        this.endSessionEndpointUri = values.endSessionEndpointUri;
        this.pushedAuthorizationRequestEndpointUri = values.pushedAuthorizationRequestEndpointUri;
        this.authorizationResponseIssuerParameterSupported = values.authorizationResponseIssuerParameterSupported;
        this.tlsClientCertificateBoundAccessTokens = values.tlsClientCertificateBoundAccessTokens;
        this.requirePushedAuthorizationRequests = values.requirePushedAuthorizationRequests;
        this.requestParameterSupported = values.requestParameterSupported;
        this.requestObjectSigningAlgorithmsSupported = values.requestObjectSigningAlgorithmsSupported.map(List::copyOf);
        this.requestObjectEncryptionAlgorithmsSupported = values.requestObjectEncryptionAlgorithmsSupported.map(List::copyOf);
        this.requestObjectContentEncryptionAlgorithmsSupported =
                values.requestObjectContentEncryptionAlgorithmsSupported.map(List::copyOf);
        this.requireSignedRequestObject = values.requireSignedRequestObject;
        this.wellKnownMetadataLoaded = values.wellKnownMetadataLoaded;
    }

    static OidcProviderMetadata fromStaticConfig(OidcTenantConfig tenantConfig) {
        OidcEndpointConfig endpoints = tenantConfig.endpoints();
        MetadataValues values = new MetadataValues();
        values.issuer = tenantConfig.issuer();
        values.wellKnownUri = wellKnownUri(values.issuer, endpoints);
        values.authorizationEndpointUri = endpoints.authorizationEndpointUri();
        values.tokenEndpointUri = endpoints.tokenEndpointUri();
        values.jwkSetUri = endpoints.jwksUri();
        values.introspectionEndpointUri = endpoints.introspectionEndpointUri();
        values.userInfoEndpointUri = endpoints.userInfoEndpointUri();
        values.endSessionEndpointUri = endpoints.endSessionEndpointUri();
        values.pushedAuthorizationRequestEndpointUri = endpoints.pushedAuthorizationRequestEndpointUri();
        return new OidcProviderMetadata(values);
    }

    static OidcProviderMetadata fromWellKnownMetadataJson(JsonObject json) {
        MetadataValues values = new MetadataValues();
        values.issuer = json.stringValue("issuer");
        values.authorizationEndpointUri = uriValue(json, "authorization_endpoint");
        values.tokenEndpointUri = uriValue(json, "token_endpoint");
        values.mutualTlsTokenEndpointUri = mutualTlsEndpointUri(json, "token_endpoint");
        values.mutualTlsPushedAuthorizationRequestEndpointUri =
                mutualTlsEndpointUri(json, "pushed_authorization_request_endpoint");
        values.mutualTlsIntrospectionEndpointUri = mutualTlsEndpointUri(json, "introspection_endpoint");
        values.mutualTlsUserInfoEndpointUri = mutualTlsEndpointUri(json, "userinfo_endpoint");
        values.jwkSetUri = uriValue(json, "jwks_uri");
        values.responseTypesSupported = stringArrayValue(json, "response_types_supported");
        values.grantTypesSupported = stringArrayValue(json, "grant_types_supported");
        values.codeChallengeMethodsSupported = stringArrayValue(json, "code_challenge_methods_supported");
        values.tokenEndpointAuthenticationMethodsSupported =
                stringArrayValue(json, "token_endpoint_auth_methods_supported");
        values.tokenEndpointAuthenticationSigningAlgorithmsSupported =
                stringArrayValue(json, "token_endpoint_auth_signing_alg_values_supported");
        values.idTokenSigningAlgorithmsSupported = stringArrayValue(json, "id_token_signing_alg_values_supported");
        values.idTokenEncryptionAlgorithmsSupported = stringArrayValue(json, "id_token_encryption_alg_values_supported");
        values.idTokenContentEncryptionAlgorithmsSupported = stringArrayValue(json, "id_token_encryption_enc_values_supported");
        values.introspectionEndpointUri = uriValue(json, "introspection_endpoint");
        values.introspectionEndpointAuthenticationMethodsSupported =
                stringArrayValue(json, "introspection_endpoint_auth_methods_supported");
        values.introspectionEndpointAuthenticationSigningAlgorithmsSupported =
                stringArrayValue(json, "introspection_endpoint_auth_signing_alg_values_supported");
        values.userInfoEndpointUri = uriValue(json, "userinfo_endpoint");
        values.userInfoSigningAlgorithmsSupported = stringArrayValue(json, "userinfo_signing_alg_values_supported");
        values.userInfoEncryptionAlgorithmsSupported = stringArrayValue(json, "userinfo_encryption_alg_values_supported");
        values.userInfoContentEncryptionAlgorithmsSupported = stringArrayValue(json, "userinfo_encryption_enc_values_supported");
        values.endSessionEndpointUri = uriValue(json, "end_session_endpoint");
        values.pushedAuthorizationRequestEndpointUri = uriValue(json, "pushed_authorization_request_endpoint");
        values.authorizationResponseIssuerParameterSupported =
                json.booleanValue("authorization_response_iss_parameter_supported").orElse(false);
        values.tlsClientCertificateBoundAccessTokens =
                json.booleanValue("tls_client_certificate_bound_access_tokens").orElse(false);
        values.requirePushedAuthorizationRequests = json.booleanValue("require_pushed_authorization_requests").orElse(false);
        values.requestParameterSupported = json.booleanValue("request_parameter_supported");
        values.requestObjectSigningAlgorithmsSupported = stringArrayValue(json, "request_object_signing_alg_values_supported");
        values.requestObjectEncryptionAlgorithmsSupported =
                stringArrayValue(json, "request_object_encryption_alg_values_supported");
        values.requestObjectContentEncryptionAlgorithmsSupported =
                stringArrayValue(json, "request_object_encryption_enc_values_supported");
        values.requireSignedRequestObject = json.booleanValue("require_signed_request_object").orElse(false);
        values.wellKnownMetadataLoaded = true;
        return new OidcProviderMetadata(values);
    }

    static Optional<URI> wellKnownUri(Optional<String> issuer, OidcEndpointConfig endpoints) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 4 Obtaining OpenID Provider Configuration Information
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
         * Quote: "OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by
         * concatenating the string `/.well-known/openid-configuration` to the Issuer."
         * Quote: "If the Issuer value contains a path component, any terminating `/` MUST be removed before appending
         * `/.well-known/openid-configuration`."
         */
        Optional<URI> configuredWellKnownUri = endpoints.wellKnownUri();
        if (configuredWellKnownUri.isPresent()) {
            return configuredWellKnownUri;
        }
        return issuer.map(OidcEndpointUris::oidcWellKnownUri);
    }

    OidcProviderMetadata mergeWellKnownMetadata(OidcProviderMetadata wellKnown) {
        validateWellKnownMetadataIssuer(wellKnown);
        MetadataValues values = new MetadataValues();
        values.issuer = issuer.or(wellKnown::issuer);
        values.wellKnownUri = wellKnownUri.or(wellKnown::wellKnownUri);
        values.authorizationEndpointUri = authorizationEndpointUri.or(wellKnown::authorizationEndpointUri);
        values.tokenEndpointUri = tokenEndpointUri.or(wellKnown::tokenEndpointUri);
        values.mutualTlsTokenEndpointUri = mutualTlsTokenEndpointUri.or(wellKnown::mutualTlsTokenEndpointUri);
        values.mutualTlsPushedAuthorizationRequestEndpointUri =
                mutualTlsPushedAuthorizationRequestEndpointUri.or(wellKnown::mutualTlsPushedAuthorizationRequestEndpointUri);
        values.mutualTlsIntrospectionEndpointUri =
                mutualTlsIntrospectionEndpointUri.or(wellKnown::mutualTlsIntrospectionEndpointUri);
        values.mutualTlsUserInfoEndpointUri = mutualTlsUserInfoEndpointUri.or(() -> wellKnown.mutualTlsUserInfoEndpointUri);
        values.jwkSetUri = jwkSetUri.or(wellKnown::jwkSetUri);
        values.responseTypesSupported = responseTypesSupported.or(wellKnown::responseTypesSupported);
        values.grantTypesSupported = grantTypesSupported.or(wellKnown::grantTypesSupported);
        values.codeChallengeMethodsSupported = codeChallengeMethodsSupported.or(wellKnown::codeChallengeMethodsSupported);
        values.tokenEndpointAuthenticationMethodsSupported =
                tokenEndpointAuthenticationMethodsSupported.or(wellKnown::tokenEndpointAuthenticationMethodsSupported);
        values.tokenEndpointAuthenticationSigningAlgorithmsSupported =
                tokenEndpointAuthenticationSigningAlgorithmsSupported
                        .or(wellKnown::tokenEndpointAuthenticationSigningAlgorithmsSupported);
        values.idTokenSigningAlgorithmsSupported =
                idTokenSigningAlgorithmsSupported.or(wellKnown::idTokenSigningAlgorithmsSupported);
        values.idTokenEncryptionAlgorithmsSupported =
                idTokenEncryptionAlgorithmsSupported.or(wellKnown::idTokenEncryptionAlgorithmsSupported);
        values.idTokenContentEncryptionAlgorithmsSupported =
                idTokenContentEncryptionAlgorithmsSupported.or(wellKnown::idTokenContentEncryptionAlgorithmsSupported);
        values.introspectionEndpointUri = introspectionEndpointUri.or(wellKnown::introspectionEndpointUri);
        values.introspectionEndpointAuthenticationMethodsSupported =
                introspectionEndpointAuthenticationMethodsSupported
                        .or(wellKnown::introspectionEndpointAuthenticationMethodsSupported);
        values.introspectionEndpointAuthenticationSigningAlgorithmsSupported =
                introspectionEndpointAuthenticationSigningAlgorithmsSupported
                        .or(wellKnown::introspectionEndpointAuthenticationSigningAlgorithmsSupported);
        values.userInfoEndpointUri = userInfoEndpointUri.or(wellKnown::userInfoEndpointUri);
        values.userInfoSigningAlgorithmsSupported =
                userInfoSigningAlgorithmsSupported.or(wellKnown::userInfoSigningAlgorithmsSupported);
        values.userInfoEncryptionAlgorithmsSupported =
                userInfoEncryptionAlgorithmsSupported.or(wellKnown::userInfoEncryptionAlgorithmsSupported);
        values.userInfoContentEncryptionAlgorithmsSupported =
                userInfoContentEncryptionAlgorithmsSupported.or(wellKnown::userInfoContentEncryptionAlgorithmsSupported);
        values.endSessionEndpointUri = endSessionEndpointUri.or(wellKnown::endSessionEndpointUri);
        values.pushedAuthorizationRequestEndpointUri =
                pushedAuthorizationRequestEndpointUri.or(wellKnown::pushedAuthorizationRequestEndpointUri);
        values.authorizationResponseIssuerParameterSupported =
                authorizationResponseIssuerParameterSupported || wellKnown.authorizationResponseIssuerParameterSupported();
        values.tlsClientCertificateBoundAccessTokens =
                tlsClientCertificateBoundAccessTokens || wellKnown.tlsClientCertificateBoundAccessTokens();
        values.requirePushedAuthorizationRequests =
                requirePushedAuthorizationRequests || wellKnown.requirePushedAuthorizationRequests();
        values.requestParameterSupported = requestParameterSupported.or(wellKnown::requestParameterSupported);
        values.requestObjectSigningAlgorithmsSupported =
                requestObjectSigningAlgorithmsSupported.or(wellKnown::requestObjectSigningAlgorithmsSupported);
        values.requestObjectEncryptionAlgorithmsSupported =
                requestObjectEncryptionAlgorithmsSupported.or(wellKnown::requestObjectEncryptionAlgorithmsSupported);
        values.requestObjectContentEncryptionAlgorithmsSupported =
                requestObjectContentEncryptionAlgorithmsSupported
                        .or(wellKnown::requestObjectContentEncryptionAlgorithmsSupported);
        values.requireSignedRequestObject = requireSignedRequestObject || wellKnown.requireSignedRequestObject();
        values.wellKnownMetadataLoaded = wellKnownMetadataLoaded || wellKnown.wellKnownMetadataLoaded();
        return new OidcProviderMetadata(values);
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

    Optional<URI> tokenEndpointUri(boolean outboundMutualTls) {
        return outboundMutualTls ? mutualTlsTokenEndpointUri.or(() -> tokenEndpointUri) : tokenEndpointUri;
    }

    Optional<URI> mutualTlsTokenEndpointUri() {
        return mutualTlsTokenEndpointUri;
    }

    Optional<URI> mutualTlsPushedAuthorizationRequestEndpointUri() {
        return mutualTlsPushedAuthorizationRequestEndpointUri;
    }

    Optional<URI> mutualTlsIntrospectionEndpointUri() {
        return mutualTlsIntrospectionEndpointUri;
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

    Optional<URI> userInfoEndpointUri(boolean outboundMutualTls) {
        return outboundMutualTls ? mutualTlsUserInfoEndpointUri.or(() -> userInfoEndpointUri) : userInfoEndpointUri;
    }

    Optional<List<String>> userInfoSigningAlgorithmsSupported() {
        return userInfoSigningAlgorithmsSupported;
    }

    Optional<List<String>> userInfoEncryptionAlgorithmsSupported() {
        return userInfoEncryptionAlgorithmsSupported;
    }

    Optional<List<String>> userInfoContentEncryptionAlgorithmsSupported() {
        return userInfoContentEncryptionAlgorithmsSupported;
    }

    Optional<URI> endSessionEndpointUri() {
        return endSessionEndpointUri;
    }

    Optional<URI> pushedAuthorizationRequestEndpointUri() {
        return pushedAuthorizationRequestEndpointUri;
    }

    Optional<URI> pushedAuthorizationRequestEndpointUri(boolean outboundMutualTls) {
        return outboundMutualTls
                ? mutualTlsPushedAuthorizationRequestEndpointUri.or(() -> pushedAuthorizationRequestEndpointUri)
                : pushedAuthorizationRequestEndpointUri;
    }

    boolean authorizationResponseIssuerParameterSupported() {
        return authorizationResponseIssuerParameterSupported;
    }

    boolean tlsClientCertificateBoundAccessTokens() {
        return tlsClientCertificateBoundAccessTokens;
    }

    boolean requirePushedAuthorizationRequests() {
        return requirePushedAuthorizationRequests;
    }

    Optional<Boolean> requestParameterSupported() {
        return requestParameterSupported;
    }

    Optional<List<String>> requestObjectSigningAlgorithmsSupported() {
        return requestObjectSigningAlgorithmsSupported;
    }

    Optional<List<String>> requestObjectEncryptionAlgorithmsSupported() {
        return requestObjectEncryptionAlgorithmsSupported;
    }

    Optional<List<String>> requestObjectContentEncryptionAlgorithmsSupported() {
        return requestObjectContentEncryptionAlgorithmsSupported;
    }

    boolean requireSignedRequestObject() {
        return requireSignedRequestObject;
    }

    boolean wellKnownMetadataLoaded() {
        return wellKnownMetadataLoaded;
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

    private static Optional<URI> mutualTlsEndpointUri(JsonObject json, String endpointName) {
        /*
         * Spec: RFC 8705, 5 Metadata for Mutual TLS Endpoint Aliases
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-5
         * Quote: "The parameter value itself consists of one or more endpoint parameters, such as `token_endpoint`,
         * `revocation_endpoint`, `introspection_endpoint`, etc., conventionally defined for the top level of
         * authorization server metadata."
         * Quote: "An OAuth client intending to do mutual TLS [...] MUST use the alias URL of the endpoint within the
         * `mtls_endpoint_aliases`, when present, in preference to the endpoint URL of the same name at the top level of
         * metadata."
         */
        return json.objectValue("mtls_endpoint_aliases")
                .flatMap(aliases -> uriValue(aliases, endpointName));
    }

    private void validateWellKnownMetadataIssuer(OidcProviderMetadata wellKnown) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 4.3 OpenID Provider Configuration Validation
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
         * Quote: "The `issuer` value returned MUST be identical to the Issuer URL that was used as the prefix to
         * `/.well-known/openid-configuration` to retrieve the configuration information."
         *
         * Spec: OpenID Connect Discovery 1.0, 5 String Operations
         * https://openid.net/specs/openid-connect-discovery-1_0.html#StringOps
         * Quote: "Comparisons between the two strings MUST be performed as a Unicode code point to code point equality
         * comparison."
         */
        String wellKnownMetadataIssuer = wellKnown.issuer()
                .orElseThrow(() -> new IllegalArgumentException("well-known metadata issuer must be present"));
        issuer.filter(configuredIssuer -> !configuredIssuer.equals(wellKnownMetadataIssuer))
                .ifPresent(_ -> {
                    throw new IllegalArgumentException("well-known metadata issuer must match configured issuer");
                });
    }

    // Construction-only named fields avoid mixing up the many optional URLs and algorithm lists in positional calls.
    private static final class MetadataValues {
        private Optional<String> issuer = Optional.empty();
        private Optional<URI> wellKnownUri = Optional.empty();
        private Optional<URI> authorizationEndpointUri = Optional.empty();
        private Optional<URI> tokenEndpointUri = Optional.empty();
        private Optional<URI> mutualTlsTokenEndpointUri = Optional.empty();
        private Optional<URI> mutualTlsPushedAuthorizationRequestEndpointUri = Optional.empty();
        private Optional<URI> mutualTlsIntrospectionEndpointUri = Optional.empty();
        private Optional<URI> mutualTlsUserInfoEndpointUri = Optional.empty();
        private Optional<URI> jwkSetUri = Optional.empty();
        private Optional<List<String>> responseTypesSupported = Optional.empty();
        private Optional<List<String>> grantTypesSupported = Optional.empty();
        private Optional<List<String>> codeChallengeMethodsSupported = Optional.empty();
        private Optional<List<String>> tokenEndpointAuthenticationMethodsSupported = Optional.empty();
        private Optional<List<String>> tokenEndpointAuthenticationSigningAlgorithmsSupported = Optional.empty();
        private Optional<List<String>> idTokenSigningAlgorithmsSupported = Optional.empty();
        private Optional<List<String>> idTokenEncryptionAlgorithmsSupported = Optional.empty();
        private Optional<List<String>> idTokenContentEncryptionAlgorithmsSupported = Optional.empty();
        private Optional<URI> introspectionEndpointUri = Optional.empty();
        private Optional<List<String>> introspectionEndpointAuthenticationMethodsSupported = Optional.empty();
        private Optional<List<String>> introspectionEndpointAuthenticationSigningAlgorithmsSupported = Optional.empty();
        private Optional<URI> userInfoEndpointUri = Optional.empty();
        private Optional<List<String>> userInfoSigningAlgorithmsSupported = Optional.empty();
        private Optional<List<String>> userInfoEncryptionAlgorithmsSupported = Optional.empty();
        private Optional<List<String>> userInfoContentEncryptionAlgorithmsSupported = Optional.empty();
        private Optional<URI> endSessionEndpointUri = Optional.empty();
        private Optional<URI> pushedAuthorizationRequestEndpointUri = Optional.empty();
        private boolean authorizationResponseIssuerParameterSupported;
        private boolean tlsClientCertificateBoundAccessTokens;
        private boolean requirePushedAuthorizationRequests;
        private Optional<Boolean> requestParameterSupported = Optional.empty();
        private Optional<List<String>> requestObjectSigningAlgorithmsSupported = Optional.empty();
        private Optional<List<String>> requestObjectEncryptionAlgorithmsSupported = Optional.empty();
        private Optional<List<String>> requestObjectContentEncryptionAlgorithmsSupported = Optional.empty();
        private boolean requireSignedRequestObject;
        private boolean wellKnownMetadataLoaded;
    }
}
