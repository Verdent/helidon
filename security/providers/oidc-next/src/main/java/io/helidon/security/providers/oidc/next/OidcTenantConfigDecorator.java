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
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import io.helidon.builder.api.Prototype;

final class OidcTenantConfigDecorator
        implements Prototype.BuilderDecorator<OidcTenantConfig.BuilderBase<?, ?>> {
    private static final String OFFLINE_ACCESS_SCOPE = "offline_access";
    private static final String PROMPT_NONE = "none";
    private static final System.Logger LOGGER = System.getLogger(OidcTenantConfigDecorator.class.getName());

    @Override
    public void decorate(OidcTenantConfig.BuilderBase<?, ?> target) {
        if (!target.enabled()) {
            return;
        }
        OidcSubjectMappingConfig subjectMapping = target.subjectMapping();
        validateClaimPaths(subjectMapping.principalIdClaimPaths(),
                           "subject-mapping.principal-id-claim-paths",
                           true);
        validateClaimPaths(subjectMapping.principalNameClaimPaths(),
                           "subject-mapping.principal-name-claim-paths",
                           false);
        validateClaimPaths(subjectMapping.roleClaimPaths(), "subject-mapping.role-claim-paths", false);
        validateClaimPaths(subjectMapping.scopeClaimPaths(), "subject-mapping.scope-claim-paths", false);
        validateIdToken(target.idToken());
        OidcClientAuthenticationConfigValidator.validateClientAssertion(target.clientAssertion());
        validateJwkSet(target.jwkSet());
        target.protectedResource()
                .map(OidcProtectedResourceConfig::tokenValidation)
                .ifPresent(OidcTenantConfigDecorator::validateTokenValidation);
        target.issuer().ifPresent(issuer -> OidcEndpointUris.validateIssuerUri(issuer, target.endpoints().tlsRequired()));
        validateAuthorizationCode(target, target.authorizationCode(), target.endpoints());
        validateUserInfo(target, target.userInfo(), target.authorizationCode(), target.endpoints());
        validateLogout(target, target.logout(), target.authorizationCode(), target.endpoints());
        validateProtectedResource(target, target.protectedResource(), target.tokenTransport(), target.endpoints());
        OidcEndpointPolicyResolver.validate(target.protectedResource(), target.authorizationCode(), target.endpointPolicy());
    }

    private static void validateJwkSet(OidcJwkSetConfig jwkSet) {
        if (jwkSet.unknownKeyIdRefreshInterval().isNegative()) {
            throw new IllegalArgumentException("jwk-set.unknown-key-id-refresh-interval must not be negative");
        }
        jwkSet.refreshInterval()
                .filter(interval -> interval.isZero() || interval.isNegative())
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException("jwk-set.refresh-interval must be positive");
                });
    }

    private static void validateIdToken(OidcIdTokenConfig idToken) {
        if (idToken.allowedAlgorithms().isEmpty()) {
            throw new IllegalArgumentException("id-token.allowed-algorithms must not be empty");
        }
        if (idToken.allowedEncryptionAlgorithms().isEmpty()) {
            throw new IllegalArgumentException("id-token.allowed-encryption-algorithms must not be empty");
        }
        if (idToken.allowedContentEncryptionAlgorithms().isEmpty()) {
            throw new IllegalArgumentException("id-token.allowed-content-encryption-algorithms must not be empty");
        }
        if (idToken.clockSkew().isNegative()) {
            throw new IllegalArgumentException("id-token.clock-skew must not be negative");
        }
        idToken.trustedAdditionalAudiences()
                .stream()
                .filter(audience -> audience == null
                        || audience.isBlank()
                        || !audience.equals(audience.strip()))
                .findFirst()
                .ifPresent(audience -> {
                    /*
                     * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                     * Quote: "The ID Token MUST be rejected if the ID Token does not list the Client as a valid
                     * audience, or if it contains additional audiences not trusted by the Client."
                     */
                    throw new IllegalArgumentException(
                            "id-token.trusted-additional-audiences must not contain blank or padded values");
                });
        idToken.allowedAlgorithms()
                .stream()
                .filter(algorithm -> algorithm == null
                        || algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip())
                        || "none".equalsIgnoreCase(algorithm))
                .findFirst()
                .ifPresent(algorithm -> {
                    /*
                     * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                     * Quote: "The Client MUST validate the signature of all other ID Tokens according to JWS [JWS]
                     * using the algorithm specified in the JWT `alg` Header Parameter."
                     * Quote: "The Client MUST use the keys provided by the Issuer."
                     */
                    throw new IllegalArgumentException(
                            "id-token.allowed-algorithms must not contain blank, padded, or none values");
                });
        idToken.allowedAlgorithms()
                .stream()
                .filter(algorithm -> algorithm != null && algorithm.toUpperCase(Locale.ROOT).startsWith("HS"))
                .findFirst()
                .ifPresent(algorithm -> {
                    /*
                     * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                     * Quote: "If the JWT `alg` Header Parameter uses a MAC based algorithm such as `HS256`, `HS384`,
                     * or `HS512`, the octets of the UTF-8 representation of the `client_secret` corresponding to the
                     * `client_id` contained in the `aud` (audience) Claim are used as the key to validate the
                     * signature."
                     */
                    throw new IllegalArgumentException(
                            "id-token.allowed-algorithms must not contain HS* algorithms");
                });
        idToken.allowedEncryptionAlgorithms()
                .stream()
                .filter(algorithm -> algorithm == null
                        || algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip()))
                .findFirst()
                .ifPresent(algorithm -> {
                    throw new IllegalArgumentException(
                            "id-token.allowed-encryption-algorithms must not contain blank or padded values");
                });
        idToken.allowedContentEncryptionAlgorithms()
                .stream()
                .filter(algorithm -> algorithm == null
                        || algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip()))
                .findFirst()
                .ifPresent(algorithm -> {
                    throw new IllegalArgumentException(
                            "id-token.allowed-content-encryption-algorithms must not contain blank or padded values");
                });
        idToken.allowedEncryptionAlgorithms()
                .stream()
                .filter("RSA1_5"::equals)
                .findFirst()
                .ifPresent(algorithm -> {
                    /*
                     * Spec: RFC 7516, 11.5 Timing Attacks
                     * https://www.rfc-editor.org/rfc/rfc7516.html#section-11.5
                     * Quote: "To mitigate the attacks described in RFC 3218, the recipient MUST NOT distinguish
                     * between format, padding, and length errors of encrypted keys."
                     */
                    LOGGER.log(System.Logger.Level.WARNING,
                               "id-token.allowed-encryption-algorithms contains RSA1_5. This should be used only for "
                                       + "legacy OpenID Providers that cannot use RSA-OAEP or RSA-OAEP-256.");
                });
    }

    private static void validateTokenValidation(OidcTokenValidationConfig tokenValidation) {
        tokenValidation.introspection()
                .clientAssertion()
                .ifPresent(OidcClientAuthenticationConfigValidator::validateClientAssertion);
        tokenValidation.allowedAlgorithms()
                .stream()
                .filter(algorithm -> algorithm != null && "none".equalsIgnoreCase(algorithm.strip()))
                .findFirst()
                .ifPresent(algorithm -> {
                    /*
                     * Spec: RFC 9068, 2.1 Header and 4 Validation
                     * https://www.rfc-editor.org/rfc/rfc9068.html#section-2.1
                     * https://www.rfc-editor.org/rfc/rfc9068.html#section-4
                     * Quote: "JWT access tokens MUST NOT use \"none\" as the signing algorithm."
                     * Quote: "The resource server MUST reject any JWT in which the value of \"alg\" is \"none\"."
                     */
                    throw new IllegalArgumentException("token-validation.allowed-algorithms must not contain none");
                });
    }

    private static void validateClaimPaths(List<String> paths, String configKey, boolean required) {
        if (required && paths.isEmpty()) {
            throw new IllegalArgumentException(configKey + " must not be empty");
        }
        paths.stream()
                .filter(path -> {
                    if (path.isBlank() || !path.equals(path.strip())) {
                        return true;
                    }
                    return Arrays.stream(path.split("\\.", -1))
                            .anyMatch(segment -> segment.isBlank() || !segment.equals(segment.strip()));
                })
                .findFirst()
                .ifPresent(path -> {
                    throw new IllegalArgumentException(configKey + " contains invalid claim path: " + path);
                });
    }

    private static void validateAuthorizationCode(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                  Optional<OidcAuthorizationCodeConfig> configuredAuthorizationCode,
                                                  OidcEndpointConfig endpoints) {
        if (configuredAuthorizationCode.isEmpty()) {
            return;
        }
        OidcAuthorizationCodeConfig authorizationCode = configuredAuthorizationCode.orElseThrow();
        if (!authorizationCode.enabled()) {
            return;
        }

        /*
         * Spec: OpenID Connect Core 1.0, 3.1.2.1 Authentication Request
         * https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
         * Quote: "OpenID Connect requests MUST contain the `openid` scope value."
         * Quote: "`client_id` REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server."
         * Quote: "`redirect_uri` REQUIRED. Redirection URI to which the response will be sent."
         */
        tenant.clientId()
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-id must be configured when Authorization Code Flow is enabled"));
        OidcClientAuthenticationConfigValidator.validateTokenEndpointAuthentication(tenant,
                                                                                   false,
                                                                                   "Authorization Code Flow");
        validatePkce(tenant, authorizationCode);
        boolean tokenEndpointTlsRequired = endpoints.tlsRequired()
                || isMutualTlsTokenEndpointAuthentication(tenant);
        OidcEndpointUris.validateRedirectionEndpointUri(OidcEndpointUris.redirectionEndpointUri(authorizationCode),
                                                        endpoints.tlsRequired());
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        OidcEndpointUris.requireEndpointOrWellKnown(endpoints.authorizationEndpointUri(),
                                                    wellKnownUri,
                                                    "authorization-endpoint-uri",
                                                    "Authorization Code Flow",
                                                    endpoints.tlsRequired(),
                                                    OidcEndpointUris::validateAuthorizationEndpointUri);
        OidcEndpointUris.requireEndpointOrWellKnown(endpoints.tokenEndpointUri(),
                                                    wellKnownUri,
                                                    "token-endpoint-uri",
                                                    "Authorization Code Flow",
                                                    tokenEndpointTlsRequired,
                                                    tokenEndpointTlsRequired,
                                                    OidcEndpointUris::validateTokenEndpointUri);
        validatePushedAuthorizationRequests(authorizationCode, endpoints, wellKnownUri);
        validateRequestObject(authorizationCode.requestObject());
        if (tenant.issuer().isEmpty() && endpoints.wellKnownUri().isEmpty()) {
            throw new IllegalArgumentException(
                    "issuer or well-known-uri must be configured when Authorization Code Flow is enabled");
        }
        OidcScopeSupport.validateConfiguredScopes(authorizationCode.scopes(), "authorization-code.scopes");
        if (!authorizationCode.scopes().contains("openid")) {
            throw new IllegalArgumentException(
                    "openid scope must be configured when Authorization Code Flow is enabled");
        }
        validateAuthorizationCodePrompts(authorizationCode.scopes(), authorizationCode.prompts());
        OidcResourceIndicators.validate(authorizationCode.resources(), "authorization-code.resources");
        tenant.cookies()
                .encryptionSecret()
                .orElseThrow(() -> new IllegalArgumentException(
                        "cookies.encryption-secret must be configured when Authorization Code Flow is enabled"));
    }

    private static void validatePushedAuthorizationRequests(OidcAuthorizationCodeConfig authorizationCode,
                                                            OidcEndpointConfig endpoints,
                                                            Optional<URI> wellKnownUri) {
        endpoints.pushedAuthorizationRequestEndpointUri()
                .ifPresent(uri -> OidcEndpointUris.validatePushedAuthorizationRequestEndpointUri(uri,
                                                                                                 endpoints.tlsRequired()));
        if (authorizationCode.pushedAuthorizationRequests() == OidcPushedAuthorizationRequestMode.REQUIRED
                && endpoints.pushedAuthorizationRequestEndpointUri().isEmpty()
                && wellKnownUri.isEmpty()) {
            throw new IllegalArgumentException(
                    "pushed-authorization-request-endpoint-uri or well-known-uri must be configured when "
                            + "authorization-code.pushed-authorization-requests is REQUIRED");
        }
    }

    private static void validateRequestObject(OidcRequestObjectConfig requestObject) {
        if (requestObject.lifetime().isZero() || requestObject.lifetime().isNegative()) {
            throw new IllegalArgumentException("authorization-code.request-object.lifetime must be positive");
        }
        requestObject.algorithm()
                .filter(algorithm -> algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip())
                        || "none".equalsIgnoreCase(algorithm))
                .ifPresent(ignored -> {
                    /*
                     * Spec: RFC 9101, 10.5 Downgrade Attack
                     * https://www.rfc-editor.org/rfc/rfc9101.html#section-10.5
                     * Quote: "It MUST also reject the request if the Request Object uses an `alg` value of `none`."
                     */
                    throw new IllegalArgumentException(
                            "authorization-code.request-object.algorithm must not be blank, padded, or none");
                });
        requestObject.algorithm()
                .filter(algorithm -> !OidcClientAuthenticationSupport.isPrivateKeyJwtAlgorithm(algorithm))
                .ifPresent(algorithm -> {
                    throw new IllegalArgumentException("authorization-code.request-object.algorithm must be one of "
                                                               + OidcClientAuthenticationSupport
                                                                       .privateKeyJwtAlgorithms());
                });
        requestObject.keyId()
                .filter(keyId -> keyId.isBlank() || !keyId.equals(keyId.strip()))
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException(
                            "authorization-code.request-object.key-id must not be blank or padded");
                });
        requestObject.jwk()
                .filter(jwk -> jwk.uri().isPresent())
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException(
                            "authorization-code.request-object.jwk must be local private key material, not a URI");
                });
        if (requestObject.mode() == OidcRequestObjectMode.REQUIRED && requestObject.jwk().isEmpty()) {
            throw new IllegalArgumentException(
                    "authorization-code.request-object.jwk must be configured when "
                            + "authorization-code.request-object.mode is REQUIRED");
        }
    }

    private static void validateAuthorizationCodePrompts(List<String> scopes, List<String> prompts) {
        /*
         * Spec: OpenID Connect Core 1.0, 3.1.2.1 Authentication Request
         * https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
         * Quote: "`prompt` OPTIONAL. Space-delimited, case-sensitive list of ASCII string values".
         * Quote: "If this parameter contains `none` with any other value, an error is returned."
         */
        Set<String> seen = new LinkedHashSet<>();
        for (String prompt : prompts) {
            if (prompt == null
                    || prompt.isBlank()
                    || !prompt.equals(prompt.strip())
                    || prompt.codePoints().anyMatch(codePoint -> codePoint <= 0x20 || codePoint > 0x7E)) {
                throw new IllegalArgumentException(
                        "authorization-code.prompts must contain visible ASCII values without whitespace");
            }
            if (!seen.add(prompt)) {
                throw new IllegalArgumentException(
                        "authorization-code.prompts contains duplicate prompt: " + prompt);
            }
        }
        if (prompts.size() > 1 && prompts.contains(PROMPT_NONE)) {
            throw new IllegalArgumentException(
                    "authorization-code.prompts cannot combine none with other prompt values");
        }
        if (scopes.contains(OFFLINE_ACCESS_SCOPE) && prompts.contains(PROMPT_NONE)) {
            /*
             * Spec: OpenID Connect Core 1.0, 11 Offline Access
             * https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
             * Quote: "When offline access is requested, a `prompt` parameter value of `consent` MUST be used".
             * Quote: "If this parameter contains `none` with any other value, an error is returned."
             */
            throw new IllegalArgumentException(
                    "authorization-code.prompts cannot contain none when authorization-code.scopes contains offline_access");
        }
    }

    private static void validatePkce(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                     OidcAuthorizationCodeConfig authorizationCode) {
        OidcClientAuthenticationMethod method =
                OidcClientAuthenticationConfigValidator.tokenEndpointAuthenticationMethod(
                        tenant.clientSecret(),
                        tenant.tokenEndpointAuthenticationMethod());
        if (method != OidcClientAuthenticationMethod.NONE) {
            return;
        }

        /*
         * Spec: RFC 9700, 2.1.1 Authorization Code Grant
         * https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1
         * Quote: "When using PKCE, clients SHOULD use PKCE code challenge methods that do not expose the PKCE verifier
         * in the authorization request."
         *
         * Spec: RFC 7636, 4.2 Client Creates the Code Challenge
         * https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
         * Quote: "If the client is capable of using \"S256\", it MUST use \"S256\", as \"S256\" is Mandatory
         * To Implement (MTI) on the server."
         */
        if (!authorizationCode.pkceRequired()) {
            throw new IllegalArgumentException(
                    "authorization-code.pkce-required cannot be false when Token Endpoint authentication is NONE");
        }
        if (authorizationCode.pkceMethod() == OidcPkceMethod.PLAIN) {
            throw new IllegalArgumentException(
                    "authorization-code.pkce-method must be S256 when Token Endpoint authentication is NONE");
        }
    }

    private static void validateUserInfo(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                         Optional<OidcUserInfoConfig> configuredUserInfo,
                                         Optional<OidcAuthorizationCodeConfig> configuredAuthorizationCode,
                                         OidcEndpointConfig endpoints) {
        if (configuredUserInfo.isEmpty()) {
            return;
        }
        OidcUserInfoConfig userInfo = configuredUserInfo.orElseThrow();
        if (!userInfo.enabled()) {
            return;
        }
        validateClaimPaths(userInfo.attributeClaimPaths(), "user-info.attribute-claim-paths", false);

        configuredAuthorizationCode
                .filter(OidcAuthorizationCodeConfig::enabled)
                .orElseThrow(() -> new IllegalArgumentException(
                        "authorization-code must be configured when UserInfo is enabled"));
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        OidcEndpointUris.requireEndpointOrWellKnown(endpoints.userInfoEndpointUri(),
                                                    wellKnownUri,
                                                    "user-info-endpoint-uri",
                                                    "UserInfo",
                                                    endpoints.tlsRequired(),
                                                    OidcEndpointUris::validateUserInfoEndpointUri);
    }

    private static void validateLogout(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                       Optional<OidcLogoutConfig> configuredLogout,
                                       Optional<OidcAuthorizationCodeConfig> configuredAuthorizationCode,
                                       OidcEndpointConfig endpoints) {
        if (configuredLogout.isEmpty()) {
            return;
        }
        OidcLogoutConfig logout = configuredLogout.orElseThrow();
        if (!logout.enabled()) {
            return;
        }
        OidcEndpointUris.validateLocalEndpointUri("local-endpoint-uri", logout.localEndpointUri());
        configuredAuthorizationCode
                .filter(OidcAuthorizationCodeConfig::enabled)
                .map(OidcEndpointUris::redirectionEndpointUri)
                .map(OidcUri::path)
                .filter(logout.localEndpointUri().getPath()::equals)
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException(
                            "local-endpoint-uri must not use the same path as redirection-endpoint-uri");
                });
        validateEndSession(tenant,
                           configuredAuthorizationCode,
                           logout.endSession()
                                   .filter(OidcEndSessionConfig::enabled),
                           endpoints);
    }

    private static void validateEndSession(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                           Optional<OidcAuthorizationCodeConfig> configuredAuthorizationCode,
                                           Optional<OidcEndSessionConfig> configuredEndSession,
                                           OidcEndpointConfig endpoints) {
        if (configuredEndSession.isEmpty()) {
            return;
        }
        OidcEndSessionConfig endSession = configuredEndSession.orElseThrow();
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        OidcEndpointUris.requireEndpointOrWellKnown(endpoints.endSessionEndpointUri(),
                                                    wellKnownUri,
                                                    "end-session-endpoint-uri",
                                                    "RP-Initiated Logout",
                                                    endpoints.tlsRequired(),
                                                    OidcEndpointUris::validateEndSessionEndpointUri);
        endSession.postLogoutRedirectUri()
                .ifPresent(uri -> OidcEndpointUris.validatePostLogoutRedirectUri("post-logout-redirect-uri",
                                                                                 uri,
                                                                                 endpoints.tlsRequired()));
        endSession.allowedPostLogoutRedirectUris()
                .forEach(uri -> OidcEndpointUris.validatePostLogoutRedirectUri("allowed-post-logout-redirect-uris",
                                                                               uri,
                                                                               endpoints.tlsRequired()));
        if (endSession.idTokenHintRequired()) {
            configuredAuthorizationCode
                    .filter(OidcAuthorizationCodeConfig::enabled)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "authorization-code must be configured when RP-Initiated Logout requires id_token_hint"));
        } else {
            tenant.clientId()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "client-id must be configured when RP-Initiated Logout can omit id_token_hint"));
        }
    }

    private static void validateProtectedResource(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                  Optional<OidcProtectedResourceConfig> configuredProtectedResource,
                                                  OidcTokenTransportConfig tokenTransport,
                                                  OidcEndpointConfig endpoints) {
        if (configuredProtectedResource.isEmpty()) {
            return;
        }
        OidcProtectedResourceConfig protectedResource = configuredProtectedResource.orElseThrow();
        OidcTokenValidationConfig tokenValidation = protectedResource.tokenValidation();
        validateBearerChallengeRealm(protectedResource.challengeRealm());
        if (!protectedResource.enabled() && tokenValidation.method().isEmpty()) {
            return;
        }

        if (protectedResource.enabled()
                && !tokenTransport.authorizationHeaderEnabled()
                && !tokenTransport.queryParameterEnabled()) {
            throw new IllegalArgumentException(
                    "at least one Bearer Token transport must be enabled when Protected Resource is enabled");
        }
        OidcTokenValidationMethod method = tokenValidation.method()
                .orElseThrow(() -> new IllegalArgumentException(
                        "token-validation.method must be configured when Protected Resource is enabled"));

        switch (method) {
        case JWT -> validateJwtAccessTokenValidation(tenant, tokenValidation, endpoints);
        case INTROSPECTION -> validateIntrospection(tenant, tokenValidation, endpoints);
        default -> throw new IllegalStateException("Unexpected token validation method: " + method);
        }
    }

    private static void validateJwtAccessTokenValidation(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                         OidcTokenValidationConfig tokenValidation,
                                                         OidcEndpointConfig endpoints) {
        if (tenant.issuer().isEmpty() && endpoints.wellKnownUri().isEmpty()) {
            throw new IllegalArgumentException(
                    "issuer or well-known-uri must be configured when JWT access-token validation is enabled");
        }
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        OidcEndpointUris.requireEndpointOrWellKnown(endpoints.jwksUri(),
                                                    wellKnownUri,
                                                    "jwks-uri",
                                                    "JWT access-token validation",
                                                    endpoints.tlsRequired(),
                                                    OidcEndpointUris::validateJwksUri);
        if (tokenValidation.audienceValidationEnabled()) {
            /*
             * Spec: RFC 9068, 2.2 Data Structure and 4 Validation
             * https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2
             * https://www.rfc-editor.org/rfc/rfc9068.html#section-4
             * Quote: "`aud` REQUIRED - as defined in Section 4.1.3 of [RFC7519]. See Section 3 for indications on
             * how an authorization server should determine the value of `aud` depending on the request."
             * Quote: "The resource server MUST validate that the `aud` claim contains a resource indicator value
             * corresponding to an identifier the resource server expects for itself."
             */
            tokenValidation.audience()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "token-validation.audience must be configured when JWT access-token audience validation "
                                    + "is enabled"));
        } else {
            LOGGER.log(System.Logger.Level.WARNING,
                       "JWT access-token audience validation is disabled. This relaxes RFC 9068 validation and "
                               + "should be used only for testing, local development, or legacy non-RFC9068 tokens.");
        }
    }

    private static void validateIntrospection(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                              OidcTokenValidationConfig tokenValidation,
                                              OidcEndpointConfig endpoints) {
        /*
         * Spec: RFC 7662, 2.1 Introspection Request
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1
         * Quote: "To prevent token scanning attacks, the endpoint MUST also require some form of authorization to
         * access this endpoint, such as client authentication as described in OAuth 2.0 [RFC6749] or a separate
         * OAuth 2.0 access token such as the bearer token described in OAuth 2.0 Bearer Token Usage [RFC6750]."
         */
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        boolean introspectionEndpointTlsRequired = endpoints.tlsRequired()
                || OidcClientAuthenticationConfigValidator.mutualTlsIntrospectionEndpointAuthentication(tokenValidation);
        OidcEndpointUris.requireEndpointOrWellKnown(endpoints.introspectionEndpointUri(),
                                                    wellKnownUri,
                                                    "introspection-endpoint-uri",
                                                    "introspection",
                                                    introspectionEndpointTlsRequired,
                                                    OidcEndpointUris::validateIntrospectionEndpointUri);
        OidcClientAuthenticationConfigValidator.validateIntrospectionEndpointAuthentication(tenant, tokenValidation);
        if (tokenValidation.audienceValidationEnabled()) {
            tokenValidation.audience()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "token-validation.audience must be configured when introspection is enabled"));
        }
    }

    private static boolean isMutualTlsTokenEndpointAuthentication(OidcTenantConfig.BuilderBase<?, ?> tenant) {
        OidcClientAuthenticationMethod method =
                OidcClientAuthenticationConfigValidator.tokenEndpointAuthenticationMethod(
                        tenant.clientSecret(),
                        tenant.tokenEndpointAuthenticationMethod());
        return method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
    }

    private static void validateBearerChallengeRealm(String realm) {
        if (realm == null || realm.isBlank() || !OidcOAuthErrorFields.validErrorDescription(realm)) {
            throw new IllegalArgumentException("protected-resource.challenge-realm must contain only RFC 6750 "
                                                       + "challenge value characters");
        }
    }
}
