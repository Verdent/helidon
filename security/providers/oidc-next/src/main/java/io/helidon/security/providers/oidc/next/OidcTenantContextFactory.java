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

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import io.helidon.webclient.api.WebClient;

final class OidcTenantContextFactory {
    private static final System.Logger LOGGER = System.getLogger(OidcTenantContextFactory.class.getName());
    private static final String AUTHORIZATION_CODE_GRANT = "authorization_code";
    private static final String CLIENT_CREDENTIALS_GRANT = "client_credentials";
    private static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String CODE_RESPONSE_TYPE = "code";
    private static final List<String> DEFAULT_GRANT_TYPES_SUPPORTED =
            List.of(AUTHORIZATION_CODE_GRANT, "implicit");
    private static final List<String> DEFAULT_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED =
            List.of(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC.wireName());

    private final TenantInitializer initializer;

    private OidcTenantContextFactory(TenantInitializer initializer) {
        this.initializer = initializer;
    }

    static OidcTenantContextFactory create() {
        return create(false, false);
    }

    static OidcTenantContextFactory create(boolean outboundTargetClientCredentialsGrant) {
        return create(outboundTargetClientCredentialsGrant, false);
    }

    static OidcTenantContextFactory create(boolean outboundTargetClientCredentialsGrant,
                                           boolean outboundTargetTokenExchange) {
        return create(defaultInitializer(outboundTargetClientCredentialsGrant, outboundTargetTokenExchange));
    }

    static OidcTenantContextFactory create(TenantInitializer initializer) {
        return new OidcTenantContextFactory(Objects.requireNonNull(initializer));
    }

    OidcTenantContext create(String tenantId, OidcTenantConfig tenantConfig) {
        if (!tenantConfig.enabled()) {
            return OidcTenantContext.disabled(tenantId, tenantConfig);
        }
        return Objects.requireNonNull(initializer.initialize(tenantId, tenantConfig),
                                      "Tenant initializer must return a context");
    }

    private static TenantInitializer defaultInitializer(boolean outboundTargetClientCredentialsGrant,
                                                       boolean outboundTargetTokenExchange) {
        return (tenantId, tenantConfig) -> {
            try {
                WebClient webClient = OidcConfigSupport.createWebClient(tenantConfig);
                OidcProviderMetadata staticMetadata = OidcProviderMetadata.fromStaticConfig(tenantConfig);
                boolean wellKnownMetadataLoaded = needsWellKnownMetadata(tenantConfig,
                                                                         staticMetadata,
                                                                         outboundTargetClientCredentialsGrant
                                                                                 || outboundTargetTokenExchange);
                OidcProviderMetadata metadata = wellKnownMetadataLoaded
                        ? new OidcProviderMetadataLoader(webClient).load(staticMetadata)
                        : staticMetadata;
                validateIssuerMetadata(tenantConfig, metadata);
                validateAuthorizationCodeMetadata(tenantConfig, metadata, wellKnownMetadataLoaded);
                validateClientCredentialsGrantMetadata(tenantConfig,
                                                       metadata,
                                                       wellKnownMetadataLoaded,
                                                       outboundTargetClientCredentialsGrant);
                validateTokenExchangeMetadata(tenantConfig,
                                              metadata,
                                              wellKnownMetadataLoaded,
                                              outboundTargetTokenExchange);
                validateJwtMetadata(tenantConfig, metadata);
                validateIntrospectionMetadata(tenantConfig, metadata);
                validateUserInfoMetadata(tenantConfig, metadata);
                validateEndSessionMetadata(tenantConfig, metadata);
                validateMutualTlsMetadata(tenantConfig, metadata);
                validateCertificateBoundAccessTokenMetadata(tenantConfig, metadata, wellKnownMetadataLoaded);
                return OidcTenantContext.ready(tenantId, tenantConfig, metadata, webClient);
            } catch (RuntimeException e) {
                LOGGER.log(System.Logger.Level.DEBUG, "OIDC tenant initialization failed: " + tenantId, e);
                return OidcTenantContext.failed(tenantId, tenantConfig, e);
            }
        };
    }

    private static boolean needsWellKnownMetadata(OidcTenantConfig tenantConfig,
                                                 OidcProviderMetadata staticMetadata,
                                                 boolean outboundTargetClientCredentialsGrant) {
        if (staticMetadata.wellKnownUri().isEmpty()) {
            return false;
        }
        OidcTokenValidationConfig tokenValidation = tenantConfig.protectedResource()
                .map(OidcProtectedResourceConfig::tokenValidation)
                .orElseGet(OidcTokenValidationConfig::create);
        if (tokenValidation.method().filter(OidcTokenValidationMethod.JWT::equals).isPresent()
                && (staticMetadata.issuer().isEmpty() || staticMetadata.jwkSetUri().isEmpty())) {
            return true;
        }
        if (tokenValidation.method().filter(OidcTokenValidationMethod.INTROSPECTION::equals).isPresent()
                && staticMetadata.introspectionEndpointUri().isEmpty()) {
            return true;
        }
        Optional<OidcAuthorizationCodeConfig> authorizationCode = tenantConfig.authorizationCode();
        if (authorizationCode.filter(OidcAuthorizationCodeConfig::enabled).isPresent()) {
            if (staticMetadata.issuer().isEmpty()
                    || staticMetadata.authorizationEndpointUri().isEmpty()
                    || staticMetadata.tokenEndpointUri().isEmpty()) {
                return true;
            }
            if (needsPushedAuthorizationRequestMetadata(authorizationCode.orElseThrow(), staticMetadata)) {
                return true;
            }
        }
        if (tenantConfig.userInfo().filter(OidcUserInfoConfig::enabled).isPresent()
                && staticMetadata.userInfoEndpointUri().isEmpty()) {
            return true;
        }
        Optional<OidcEndSessionConfig> endSession = tenantConfig.logout()
                .filter(OidcLogoutConfig::enabled)
                .flatMap(OidcLogoutConfig::endSession)
                .filter(OidcEndSessionConfig::enabled);
        if (endSession.isPresent() && staticMetadata.endSessionEndpointUri().isEmpty()) {
            return true;
        }
        return outboundTargetClientCredentialsGrant && staticMetadata.tokenEndpointUri().isEmpty();
    }

    private static boolean needsPushedAuthorizationRequestMetadata(OidcAuthorizationCodeConfig authorizationCode,
                                                                   OidcProviderMetadata staticMetadata) {
        if (staticMetadata.wellKnownUri().isEmpty()) {
            return false;
        }
        OidcPushedAuthorizationRequestMode mode = authorizationCode.pushedAuthorizationRequests();
        return switch (mode) {
        case DISABLED, AUTO -> false;
        case REQUIRED -> staticMetadata.pushedAuthorizationRequestEndpointUri().isEmpty();
        };
    }

    private static void validateIssuerMetadata(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        metadata.issuerUri()
                .ifPresent(uri -> OidcConfigSupport.validateIssuerUri(uri, tenantConfig.endpoints().tlsRequired()));
    }

    private static void validateAuthorizationCodeMetadata(OidcTenantConfig tenantConfig,
                                                          OidcProviderMetadata metadata,
                                                          boolean wellKnownMetadataLoaded) {
        if (tenantConfig.authorizationCode().filter(OidcAuthorizationCodeConfig::enabled).isEmpty()) {
            return;
        }

         /*
          * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
          * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
          * Quote: "`issuer` REQUIRED. URL using the `https` scheme with no query or fragment components that the OP
          * asserts as its Issuer Identifier."
          * Quote: "`authorization_endpoint` REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint."
          * Quote: "`token_endpoint` URL of the OP's OAuth 2.0 Token Endpoint. This is REQUIRED unless only the
          * Implicit Flow is used."
         */
        metadata.issuer()
                .orElseThrow(() -> new IllegalStateException(
                        "well-known metadata issuer must be present for Authorization Code Flow"));
        metadata.authorizationEndpointUri()
                .ifPresentOrElse(uri -> OidcConfigSupport.validateAuthorizationEndpointUri(
                                         uri,
                                         tenantConfig.endpoints().tlsRequired()),
                                 () -> {
                                     throw new IllegalStateException(
                                             "well-known metadata authorization_endpoint must be present for "
                                                     + "Authorization Code Flow");
                                 });
        metadata.tokenEndpointUri()
                .ifPresentOrElse(uri -> OidcConfigSupport.validateTokenEndpointUri(
                                         uri,
                                         tokenEndpointTlsRequired(tenantConfig)),
                                 () -> {
                                     throw new IllegalStateException(
                                             "well-known metadata token_endpoint must be present for "
                                                     + "Authorization Code Flow");
                                 });
        validateAuthorizationCodeCapabilityMetadata(tenantConfig, metadata, wellKnownMetadataLoaded);
        validateTokenEndpointAuthenticationMetadata(tenantConfig, metadata, wellKnownMetadataLoaded);
        validateIdTokenMetadata(tenantConfig, metadata, wellKnownMetadataLoaded);
        validatePushedAuthorizationRequestMetadata(tenantConfig, metadata, wellKnownMetadataLoaded);
    }

    private static void validateAuthorizationCodeCapabilityMetadata(OidcTenantConfig tenantConfig,
                                                                    OidcProviderMetadata metadata,
                                                                    boolean wellKnownMetadataLoaded) {
        if (!wellKnownMetadataLoaded) {
            return;
        }

        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "`response_types_supported` REQUIRED. JSON array containing a list of the OAuth 2.0 `response_type`
         * values that this OP supports."
         * Quote: "Dynamic OpenID Providers MUST support the `code`, `id_token`, and the `id_token token` Response
         * Type values."
         */
        List<String> responseTypes = metadata.responseTypesSupported()
                .orElseThrow(() -> new IllegalStateException(
                        "well-known metadata response_types_supported must be present for Authorization Code Flow"));
        if (!responseTypes.contains(CODE_RESPONSE_TYPE)) {
            throw new IllegalStateException(
                    "well-known metadata response_types_supported must include " + CODE_RESPONSE_TYPE);
        }

        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "If omitted, the default value is `[\"authorization_code\", \"implicit\"]`."
         */
        if (!metadata.grantTypesSupported().orElse(DEFAULT_GRANT_TYPES_SUPPORTED).contains(AUTHORIZATION_CODE_GRANT)) {
            throw new IllegalStateException(
                    "well-known metadata grant_types_supported must include " + AUTHORIZATION_CODE_GRANT);
        }

        OidcAuthorizationCodeConfig authorizationCode = tenantConfig.authorizationCode()
                .orElseThrow();
        if (!authorizationCode.pkceRequired()) {
            return;
        }
        String pkceMethod = authorizationCode.pkceMethod().wireName();
        /*
         * Spec: RFC 8414, 2 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
         * Quote: "If omitted, the authorization server does not support PKCE."
         */
        List<String> codeChallengeMethods = metadata.codeChallengeMethodsSupported()
                .orElseThrow(() -> new IllegalStateException(
                        "well-known metadata code_challenge_methods_supported must be present when PKCE is enabled"));
        if (!codeChallengeMethods.contains(pkceMethod)) {
            throw new IllegalStateException(
                    "well-known metadata code_challenge_methods_supported must include " + pkceMethod);
        }
    }

    private static void validateIdTokenMetadata(OidcTenantConfig tenantConfig,
                                                OidcProviderMetadata metadata,
                                                boolean wellKnownMetadataLoaded) {
        if (!wellKnownMetadataLoaded) {
            return;
        }
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "`id_token_signing_alg_values_supported` REQUIRED. JSON array containing a list of the JWS signing
         * algorithms (`alg` values) supported by the OP for the ID Token to encode the Claims in a JWT."
         * Quote: "The algorithm `RS256` MUST be included."
         */
        List<String> supportedAlgorithms = metadata.idTokenSigningAlgorithmsSupported()
                .orElseThrow(() -> new IllegalStateException(
                        "well-known metadata id_token_signing_alg_values_supported must be present for "
                                + "Authorization Code Flow"));
        boolean supported = tenantConfig.idToken()
                .allowedAlgorithms()
                .stream()
                .anyMatch(supportedAlgorithms::contains);
        if (!supported) {
            throw new IllegalStateException(
                    "well-known metadata id_token_signing_alg_values_supported must include at least one configured "
                            + "ID Token algorithm");
        }
        validateOptionalIdTokenEncryptionMetadata(tenantConfig, metadata);
    }

    private static void validatePushedAuthorizationRequestMetadata(OidcTenantConfig tenantConfig,
                                                                  OidcProviderMetadata metadata,
                                                                  boolean wellKnownMetadataLoaded) {
        OidcAuthorizationCodeConfig authorizationCode = tenantConfig.authorizationCode().orElseThrow();
        OidcPushedAuthorizationRequestMode mode = authorizationCode.pushedAuthorizationRequests();
        metadata.pushedAuthorizationRequestEndpointUri()
                .ifPresent(uri -> OidcConfigSupport.validatePushedAuthorizationRequestEndpointUri(
                        uri,
                        tenantConfig.endpoints().tlsRequired()));

        /*
         * Spec: RFC 9126, 4 Authorization Request and 5 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc9126.html#section-4
         * https://www.rfc-editor.org/rfc/rfc9126.html#section-5
         * Quote: "PAR be the only means for a client to pass authorization request data."
         * Quote: "pushed_authorization_request_endpoint is sufficient for a client to determine that it may use the
         * PAR flow."
         */
        if (wellKnownMetadataLoaded
                && metadata.requirePushedAuthorizationRequests()
                && mode == OidcPushedAuthorizationRequestMode.DISABLED) {
            throw new IllegalStateException(
                    "well-known metadata require_pushed_authorization_requests cannot be true when "
                            + "authorization-code.pushed-authorization-requests is DISABLED");
        }
        if ((mode == OidcPushedAuthorizationRequestMode.REQUIRED
                || mode == OidcPushedAuthorizationRequestMode.AUTO && metadata.requirePushedAuthorizationRequests())
                && metadata.pushedAuthorizationRequestEndpointUri().isEmpty()) {
            throw new IllegalStateException(
                    "well-known metadata pushed_authorization_request_endpoint must be present when Pushed "
                            + "Authorization Requests are required");
        }
    }

    private static void validateOptionalIdTokenEncryptionMetadata(OidcTenantConfig tenantConfig,
                                                                  OidcProviderMetadata metadata) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "`id_token_encryption_alg_values_supported` OPTIONAL. JSON array containing a list of the JWE
         * encryption algorithms (`alg` values) supported by the OP for the ID Token to encode the Claims in a JWT."
         * Quote: "`id_token_encryption_enc_values_supported` OPTIONAL. JSON array containing a list of the JWE
         * encryption algorithms (`enc` values) supported by the OP for the ID Token to encode the Claims in a JWT."
         */
        metadata.idTokenEncryptionAlgorithmsSupported()
                .filter(supportedAlgorithms -> tenantConfig.idToken()
                        .allowedEncryptionAlgorithms()
                        .stream()
                        .noneMatch(supportedAlgorithms::contains))
                .ifPresent(supportedAlgorithms -> {
                    throw new IllegalStateException(
                            "well-known metadata id_token_encryption_alg_values_supported must include at least one "
                                    + "configured ID Token encryption algorithm");
                });
        metadata.idTokenContentEncryptionAlgorithmsSupported()
                .filter(supportedAlgorithms -> tenantConfig.idToken()
                        .allowedContentEncryptionAlgorithms()
                        .stream()
                        .noneMatch(supportedAlgorithms::contains))
                .ifPresent(supportedAlgorithms -> {
                    throw new IllegalStateException(
                            "well-known metadata id_token_encryption_enc_values_supported must include at least one "
                                    + "configured ID Token content encryption algorithm");
                });
    }

    private static void validateClientCredentialsGrantMetadata(OidcTenantConfig tenantConfig,
                                                               OidcProviderMetadata metadata,
                                                               boolean wellKnownMetadataLoaded,
                                                               boolean outboundTargetClientCredentialsGrant) {
        if (!outboundTargetClientCredentialsGrant) {
            return;
        }

        /*
         * Spec: RFC 8414, 2 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
         * Quote: "`token_endpoint` OPTIONAL.  URL of the authorization server's OAuth 2.0 token endpoint".
         */
        metadata.tokenEndpointUri()
                .ifPresentOrElse(uri -> OidcConfigSupport.validateTokenEndpointUri(
                                         uri,
                                         tokenEndpointTlsRequired(tenantConfig)),
                                 () -> {
                                     throw new IllegalStateException(
                                             "well-known metadata token_endpoint must be present for "
                                                     + "Client Credentials Grant");
                                 });
        validateClientCredentialsCapabilityMetadata(metadata, wellKnownMetadataLoaded);
        validateTokenEndpointAuthenticationMetadata(tenantConfig, metadata, wellKnownMetadataLoaded);
    }

    private static void validateClientCredentialsCapabilityMetadata(OidcProviderMetadata metadata,
                                                                    boolean wellKnownMetadataLoaded) {
        if (!wellKnownMetadataLoaded) {
            return;
        }

        /*
         * Spec: RFC 8414, 2 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
         * Quote: "`grant_types_supported` OPTIONAL. JSON array containing a list of the OAuth 2.0 grant type values
         * that this authorization server supports."
         * Quote: "If omitted, the default value is `[\"authorization_code\", \"implicit\"]`."
         */
        if (!metadata.grantTypesSupported().orElse(DEFAULT_GRANT_TYPES_SUPPORTED).contains(CLIENT_CREDENTIALS_GRANT)) {
            throw new IllegalStateException(
                    "well-known metadata grant_types_supported must include " + CLIENT_CREDENTIALS_GRANT);
        }
    }

    private static void validateTokenExchangeMetadata(OidcTenantConfig tenantConfig,
                                                      OidcProviderMetadata metadata,
                                                      boolean wellKnownMetadataLoaded,
                                                      boolean outboundTargetTokenExchange) {
        if (!outboundTargetTokenExchange) {
            return;
        }

        /*
         * Spec: RFC 8414, 2 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
         * Quote: "`token_endpoint` OPTIONAL.  URL of the authorization server's OAuth 2.0 token endpoint".
         */
        metadata.tokenEndpointUri()
                .ifPresentOrElse(uri -> OidcConfigSupport.validateTokenEndpointUri(
                                         uri,
                                         tokenEndpointTlsRequired(tenantConfig)),
                                 () -> {
                                     throw new IllegalStateException(
                                             "well-known metadata token_endpoint must be present for Token Exchange");
                                 });
        validateTokenExchangeCapabilityMetadata(metadata, wellKnownMetadataLoaded);
        validateTokenEndpointAuthenticationMetadata(tenantConfig, metadata, wellKnownMetadataLoaded);
    }

    private static void validateTokenExchangeCapabilityMetadata(OidcProviderMetadata metadata,
                                                               boolean wellKnownMetadataLoaded) {
        if (!wellKnownMetadataLoaded) {
            return;
        }

        /*
         * Spec: RFC 8414, 2 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
         * Quote: "`grant_types_supported` OPTIONAL. JSON array containing a list of the OAuth 2.0 grant type values
         * that this authorization server supports."
         *
         * Spec: RFC 8693, 7.1 OAuth URI Registration
         * https://www.rfc-editor.org/rfc/rfc8693.html#section-7.1
         * Quote: "URN: urn:ietf:params:oauth:grant-type:token-exchange"
         */
        metadata.grantTypesSupported()
                .filter(grantTypes -> !grantTypes.contains(TOKEN_EXCHANGE_GRANT))
                .ifPresent(grantTypes -> {
                    throw new IllegalStateException(
                            "well-known metadata grant_types_supported must include " + TOKEN_EXCHANGE_GRANT);
                });
    }

    private static void validateTokenEndpointAuthenticationMetadata(OidcTenantConfig tenantConfig,
                                                                    OidcProviderMetadata metadata,
                                                                    boolean wellKnownMetadataLoaded) {
        if (!wellKnownMetadataLoaded) {
            return;
        }

        OidcClientAuthenticationMethod method =
                OidcClientAuthenticationSupport.tokenEndpointAuthenticationMethod(tenantConfig);
        /*
         * Spec: RFC 8414, 2 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
         * Quote: "If omitted, the default is \"client_secret_basic\" -- the HTTP Basic Authentication Scheme".
         */
        List<String> supportedMethods = metadata.tokenEndpointAuthenticationMethodsSupported()
                .orElse(DEFAULT_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED);
        if (!supportedMethods.contains(method.wireName())) {
            throw new IllegalStateException(
                    "well-known metadata token_endpoint_auth_methods_supported must include " + method.wireName());
        }

        if (method != OidcClientAuthenticationMethod.CLIENT_SECRET_JWT
                && method != OidcClientAuthenticationMethod.PRIVATE_KEY_JWT) {
            return;
        }
        OidcClientAuthenticationSupport clientAuthentication =
                OidcClientAuthenticationSupport.tokenEndpoint(tenantConfig);
        String algorithm = clientAuthentication.clientAssertionAlgorithm().orElseThrow();
        List<String> supportedAlgorithms = metadata.tokenEndpointAuthenticationSigningAlgorithmsSupported()
                .orElseThrow(() -> new IllegalStateException(
                        "well-known metadata token_endpoint_auth_signing_alg_values_supported must be present for "
                                + method.wireName()));
        /*
         * Spec: RFC 8414, 2 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
         * Quote: "This metadata entry MUST be present if either of these authentication methods are specified in the
         * `token_endpoint_auth_methods_supported` entry."
         * Quote: "No default algorithms are implied if this entry is omitted."
         * Quote: "The value \"none\" MUST NOT be used."
         */
        if (supportedAlgorithms.contains("none")) {
            throw new IllegalStateException(
                    "well-known metadata token_endpoint_auth_signing_alg_values_supported must not include none");
        }
        if (!supportedAlgorithms.contains(algorithm)) {
            throw new IllegalStateException(
                    "well-known metadata token_endpoint_auth_signing_alg_values_supported must include " + algorithm);
        }
    }

    private static boolean tokenEndpointTlsRequired(OidcTenantConfig tenantConfig) {
        return tenantConfig.endpoints().tlsRequired() || mutualTlsTokenEndpointAuthentication(tenantConfig);
    }

    private static boolean mutualTlsTokenEndpointAuthentication(OidcTenantConfig tenantConfig) {
        OidcClientAuthenticationMethod method =
                OidcClientAuthenticationSupport.tokenEndpointAuthenticationMethod(tenantConfig);
        return method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
    }

    private static boolean introspectionEndpointTlsRequired(OidcTenantConfig tenantConfig) {
        return tenantConfig.endpoints().tlsRequired() || mutualTlsIntrospectionEndpointAuthentication(tenantConfig);
    }

    private static boolean mutualTlsIntrospectionEndpointAuthentication(OidcTenantConfig tenantConfig) {
        OidcClientAuthenticationMethod method =
                OidcClientAuthenticationSupport.introspectionEndpointAuthenticationMethod(tenantConfig);
        return method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
    }

    private static void validateJwtMetadata(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        OidcTokenValidationConfig tokenValidation = tenantConfig.protectedResource()
                .map(OidcProtectedResourceConfig::tokenValidation)
                .orElseGet(OidcTokenValidationConfig::create);
        if (tokenValidation.method().filter(OidcTokenValidationMethod.JWT::equals).isEmpty()) {
            return;
        }

        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "`jwks_uri` REQUIRED. URL of the OP's JSON Web Key Set [JWK] document."
         */
        metadata.jwkSetUri()
                .ifPresentOrElse(uri -> OidcConfigSupport.validateJwksUri(uri, tenantConfig.endpoints().tlsRequired()),
                                 () -> {
                                     throw new IllegalStateException(
                                             "well-known metadata jwks_uri must be present for JWT access-token "
                                                     + "validation");
                                 });
    }

    private static void validateIntrospectionMetadata(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        OidcTokenValidationConfig tokenValidation = tenantConfig.protectedResource()
                .map(OidcProtectedResourceConfig::tokenValidation)
                .orElseGet(OidcTokenValidationConfig::create);
        if (tokenValidation.method().filter(OidcTokenValidationMethod.INTROSPECTION::equals).isEmpty()) {
            return;
        }

        /*
         * Spec: RFC 8414, 2 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
         * Quote: "`introspection_endpoint` OPTIONAL.  URL of the authorization server's OAuth 2.0 introspection
         * endpoint".
         */
        metadata.introspectionEndpointUri()
                .ifPresentOrElse(uri -> OidcConfigSupport.validateIntrospectionEndpointUri(
                                         uri,
                                         introspectionEndpointTlsRequired(tenantConfig)),
                                 () -> {
                                     throw new IllegalStateException(
                                             "well-known metadata introspection_endpoint must be present for "
                                                     + "introspection");
                                 });
        validateIntrospectionAuthenticationMetadata(tenantConfig, metadata);
    }

    private static void validateIntrospectionAuthenticationMetadata(OidcTenantConfig tenantConfig,
                                                                    OidcProviderMetadata metadata) {
        OidcClientAuthenticationMethod method =
                OidcClientAuthenticationSupport.introspectionEndpointAuthenticationMethod(tenantConfig);
        metadata.introspectionEndpointAuthenticationMethodsSupported()
                .filter(methods -> !methods.contains(method.wireName()))
                .ifPresent(methods -> {
                     /*
                      * Spec: RFC 8414, 2 Authorization Server Metadata
                      * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
                      * Quote: "`introspection_endpoint_auth_methods_supported` OPTIONAL. JSON array containing a list
                      * of client authentication methods supported by this introspection endpoint."
                     */
                    throw new IllegalStateException(
                            "well-known metadata introspection_endpoint_auth_methods_supported must include "
                                    + method.wireName());
                });
        if (method != OidcClientAuthenticationMethod.CLIENT_SECRET_JWT
                && method != OidcClientAuthenticationMethod.PRIVATE_KEY_JWT) {
            return;
        }
        OidcClientAuthenticationSupport clientAuthentication =
                OidcClientAuthenticationSupport.introspectionEndpoint(tenantConfig);
        String algorithm = clientAuthentication.clientAssertionAlgorithm().orElseThrow();
        metadata.introspectionEndpointAuthenticationSigningAlgorithmsSupported()
                .ifPresentOrElse(algorithms -> {
                    if (!algorithms.contains(algorithm)) {
                        throw new IllegalStateException(
                                "well-known metadata introspection_endpoint_auth_signing_alg_values_supported must "
                                        + "include " + algorithm);
                    }
                }, () -> {
                    /*
                     * Spec: RFC 8414, 2 Authorization Server Metadata
                     * https://www.rfc-editor.org/rfc/rfc8414.html#section-2
                     * Quote: "`introspection_endpoint_auth_signing_alg_values_supported` OPTIONAL. JSON array
                     * containing a list of the JWS signing algorithms (`alg` values) supported by the introspection
                     * endpoint for the signature on the JWT used to authenticate the client at the introspection
                     * endpoint for the `private_key_jwt` and `client_secret_jwt` authentication methods."
                     * Quote: "No default algorithms are implied if this entry is omitted."
                     */
                    throw new IllegalStateException(
                            "well-known metadata introspection_endpoint_auth_signing_alg_values_supported must be "
                                    + "present for " + method.wireName());
                });
    }

    private static void validateUserInfoMetadata(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        if (tenantConfig.userInfo().filter(OidcUserInfoConfig::enabled).isEmpty()) {
            return;
        }

        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "`userinfo_endpoint` OPTIONAL. URL of the OP's UserInfo Endpoint."
         */
        metadata.userInfoEndpointUri()
                .ifPresentOrElse(uri -> OidcConfigSupport.validateUserInfoEndpointUri(
                                         uri,
                                         tenantConfig.endpoints().tlsRequired()),
                                 () -> {
                                     throw new IllegalStateException(
                                             "well-known metadata userinfo_endpoint must be present for UserInfo");
                                 });
    }

    private static void validateEndSessionMetadata(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        Optional<OidcEndSessionConfig> endSession = tenantConfig.logout()
                .filter(OidcLogoutConfig::enabled)
                .flatMap(OidcLogoutConfig::endSession)
                .filter(OidcEndSessionConfig::enabled);
        if (endSession.isEmpty()) {
            return;
        }

        /*
         * Spec: OpenID Connect RP-Initiated Logout 1.0, 2.1 OpenID Provider Discovery Metadata
         * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
         * Quote: "`end_session_endpoint` REQUIRED. URL at the OP to which an RP can perform a redirect to request that
         * the End-User be logged out at the OP."
         * Quote: "This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components."
         */
        metadata.endSessionEndpointUri()
                .ifPresentOrElse(uri -> OidcConfigSupport.validateEndSessionEndpointUri(
                                         uri,
                                         tenantConfig.endpoints().tlsRequired()),
                                 () -> {
                                     throw new IllegalStateException(
                                             "well-known metadata end_session_endpoint must be present for "
                                                     + "RP-Initiated Logout");
                                 });
    }

    static void validateMutualTlsMetadata(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        if (!mutualTlsTokenEndpointAuthentication(tenantConfig)) {
            return;
        }

        /*
         * Spec: RFC 8705, 5 Metadata for Mutual TLS Endpoint Aliases
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-5
         * Quote: "`mtls_endpoint_aliases` OPTIONAL. A JSON object containing alternative authorization server endpoints
         * that, when present, an OAuth client intending to do mutual TLS uses in preference to the conventional
         * endpoints."
         */
        metadata.mutualTlsTokenEndpointUri()
                .or(metadata::tokenEndpointUri)
                .ifPresent(uri -> OidcConfigSupport.validateTokenEndpointUri(uri, true));
    }

    private static void validateCertificateBoundAccessTokenMetadata(OidcTenantConfig tenantConfig,
                                                                    OidcProviderMetadata metadata,
                                                                    boolean wellKnownMetadataLoaded) {
        if (!wellKnownMetadataLoaded) {
            return;
        }

        OidcTokenValidationConfig tokenValidation = tenantConfig.protectedResource()
                .map(OidcProtectedResourceConfig::tokenValidation)
                .orElseGet(OidcTokenValidationConfig::create);
        if (tokenValidation.certificateBoundAccessTokens().mode()
                == OidcCertificateBoundAccessTokenMode.DISABLED) {
            return;
        }

        /*
         * Spec: RFC 8705, 3.3 Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-3.3
         * Quote: "`tls_client_certificate_bound_access_tokens` OPTIONAL. Boolean value indicating server support for
         * mutual-TLS client certificate-bound access tokens."
         * Quote: "If omitted, the default value is `false`."
         */
        if (!metadata.tlsClientCertificateBoundAccessTokens()) {
            throw new IllegalStateException(
                    "well-known metadata tls_client_certificate_bound_access_tokens must be true");
        }
    }

    @FunctionalInterface
    interface TenantInitializer {
        OidcTenantContext initialize(String tenantId, OidcTenantConfig tenantConfig);
    }
}
