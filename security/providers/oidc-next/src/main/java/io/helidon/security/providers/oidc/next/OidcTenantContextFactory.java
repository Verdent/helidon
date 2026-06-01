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

import java.util.Objects;
import java.util.Optional;

import io.helidon.webclient.api.WebClient;

final class OidcTenantContextFactory {
    private static final System.Logger LOGGER = System.getLogger(OidcTenantContextFactory.class.getName());

    private final TenantInitializer initializer;

    private OidcTenantContextFactory(TenantInitializer initializer) {
        this.initializer = initializer;
    }

    static OidcTenantContextFactory create() {
        return create(false);
    }

    static OidcTenantContextFactory create(boolean outboundTargetClientCredentialsGrant) {
        return create(defaultInitializer(outboundTargetClientCredentialsGrant));
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

    private static TenantInitializer defaultInitializer(boolean outboundTargetClientCredentialsGrant) {
        return (tenantId, tenantConfig) -> {
            try {
                WebClient webClient = OidcConfigSupport.createWebClient(tenantConfig);
                OidcProviderMetadata staticMetadata = OidcProviderMetadata.fromStaticConfig(tenantConfig);
                OidcProviderMetadata metadata = needsWellKnownMetadata(tenantConfig,
                                                                       staticMetadata,
                                                                       outboundTargetClientCredentialsGrant)
                        ? new OidcProviderMetadataLoader(webClient).load(staticMetadata)
                        : staticMetadata;
                validateIssuerMetadata(tenantConfig, metadata);
                validateAuthorizationCodeMetadata(tenantConfig, metadata);
                validateClientCredentialsGrantMetadata(tenantConfig,
                                                       metadata,
                                                       outboundTargetClientCredentialsGrant);
                validateJwtMetadata(tenantConfig, metadata);
                validateIntrospectionMetadata(tenantConfig, metadata);
                validateUserInfoMetadata(tenantConfig, metadata);
                validateEndSessionMetadata(tenantConfig, metadata);
                validateMutualTlsMetadata(tenantConfig, metadata);
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
        if (authorizationCode.filter(OidcAuthorizationCodeConfig::enabled).isPresent()
                && (staticMetadata.authorizationEndpointUri().isEmpty()
                || staticMetadata.tokenEndpointUri().isEmpty())) {
            return true;
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

    private static void validateIssuerMetadata(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        metadata.issuer()
                .ifPresent(uri -> OidcConfigSupport.validateIssuerUri(uri, tenantConfig.endpoints().tlsRequired()));
    }

    private static void validateAuthorizationCodeMetadata(OidcTenantConfig tenantConfig,
                                                          OidcProviderMetadata metadata) {
        if (tenantConfig.authorizationCode().filter(OidcAuthorizationCodeConfig::enabled).isEmpty()) {
            return;
        }

        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quotes: "`authorization_endpoint` REQUIRED"; "`token_endpoint` ... REQUIRED unless".
         */
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
    }

    private static void validateClientCredentialsGrantMetadata(OidcTenantConfig tenantConfig,
                                                               OidcProviderMetadata metadata,
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
         * Quote: "REQUIRED. URL of the OP's JSON Web Key Set [JWK] document".
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
                                         tenantConfig.endpoints().tlsRequired()),
                                 () -> {
                                     throw new IllegalStateException(
                                             "well-known metadata introspection_endpoint must be present for "
                                                     + "introspection");
                                 });
    }

    private static void validateUserInfoMetadata(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        if (tenantConfig.userInfo().filter(OidcUserInfoConfig::enabled).isEmpty()) {
            return;
        }

        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "OPTIONAL. URL of the OP's UserInfo Endpoint".
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
         * Quotes: "OPTIONAL. URL at the OP"; "This URL MUST use the `https` scheme".
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
         * Quote: "`mtls_endpoint_aliases` consists of one or more endpoint aliases".
         */
        metadata.mutualTlsTokenEndpointUri()
                .or(metadata::tokenEndpointUri)
                .ifPresent(uri -> OidcConfigSupport.validateTokenEndpointUri(uri, true));
    }

    @FunctionalInterface
    interface TenantInitializer {
        OidcTenantContext initialize(String tenantId, OidcTenantConfig tenantConfig);
    }
}
