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
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Prototype;
import io.helidon.common.tls.ConfiguredTlsManager;
import io.helidon.common.tls.TlsConfig;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;

final class OidcConfigSupport {
    private static final String TENANT_VARIABLE = "{tenant}";
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT =
            WebClientConfig.create().socketOptions().readTimeout();

    private OidcConfigSupport() {
    }

    static Optional<OidcEndpointPolicy> endpointPolicy(OidcTenantConfig tenant) {
        boolean bearerTokenAuthentication = tenant.protectedResource()
                .filter(OidcProtectedResourceConfig::enabled)
                .isPresent();
        boolean authorizationCodeFlow = tenant.authorizationCode()
                .filter(OidcAuthorizationCodeConfig::enabled)
                .isPresent();

        if (bearerTokenAuthentication && authorizationCodeFlow) {
            return Optional.of(OidcEndpointPolicy.protectedResourceAndAuthorizationCodeFlow());
        }
        if (bearerTokenAuthentication) {
            return Optional.of(OidcEndpointPolicy.protectedResource());
        }
        if (authorizationCodeFlow) {
            return Optional.of(OidcEndpointPolicy.authorizationCodeFlow());
        }
        return Optional.empty();
    }

    static Optional<OidcOutboundPolicy> outboundPolicy(OidcTenantConfig tenant) {
        OidcOutboundConfig outbound = tenant.outbound();
        boolean tokenPropagation = outbound.tokenPropagationEnabled();
        boolean clientCredentialsGrant = outbound.clientCredentialsGrantEnabled();

        if (tokenPropagation && clientCredentialsGrant) {
            return Optional.of(OidcOutboundPolicy.tokenPropagationAndClientCredentialsGrant());
        }
        if (tokenPropagation) {
            return Optional.of(OidcOutboundPolicy.tokenPropagation());
        }
        if (clientCredentialsGrant) {
            return Optional.of(OidcOutboundPolicy.clientCredentialsGrant());
        }
        return Optional.empty();
    }

    static boolean targetClientCredentialsGrantEnabled(List<OutboundTarget> outboundTargets) {
        return outboundTargets.stream()
                .map(OidcOutboundPolicy::fromTarget)
                .flatMap(Optional::stream)
                .anyMatch(OidcOutboundPolicy::clientCredentialsGrantEnabled);
    }

    static WebClient createWebClient(OidcTenantConfig tenantConfig) {
        WebClientConfig configured = tenantConfig.webClient();
        if (configured.readTimeout().isPresent()
                || !WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT.equals(configured.socketOptions().readTimeout())) {
            return WebClient.create(configured);
        }
        return WebClient.create(WebClientConfig.builder()
                                        .from(configured)
                                        .readTimeout(DEFAULT_READ_TIMEOUT)
                                        .buildPrototype());
    }

    static final class ProviderDecorator implements Prototype.BuilderDecorator<OidcProviderConfig.BuilderBase<?, ?>> {
        @Override
        public void decorate(OidcProviderConfig.BuilderBase<?, ?> target) {
            if (target.defaultTenant().isEmpty() && target.tenants().size() == 1) {
                target.defaultTenant(target.tenants().keySet().iterator().next());
            }

            target.defaultTenant().ifPresent(defaultTenant -> {
                if (!target.tenants().containsKey(defaultTenant)) {
                    throw new IllegalArgumentException("default-tenant must reference a configured tenant");
                }
            });

            if (targetClientCredentialsGrantEnabled(target.outboundTargets())) {
                target.tenants()
                        .values()
                        .stream()
                        .filter(OidcTenantConfig::enabled)
                        .forEach(tenant -> validateClientCredentialsGrant(tenant,
                                                                          tenant.endpoints(),
                                                                          "Client Credentials Grant"));
            }
        }
    }

    static final class TenantDecorator implements Prototype.BuilderDecorator<OidcTenantConfig.BuilderBase<?, ?>> {
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
            validateClientAssertion(target.clientAssertion());
            target.issuer().ifPresent(uri -> validateIssuerUri(uri, target.endpoints().tlsRequired()));
            validateAuthorizationCode(target, target.authorizationCode(), target.endpoints());
            validateUserInfo(target, target.userInfo(), target.authorizationCode(), target.endpoints());
            validateLogout(target, target.logout(), target.authorizationCode(), target.endpoints());
            validateProtectedResource(target, target.protectedResource(), target.tokenTransport(), target.endpoints());
            validateOutbound(target, target.outbound(), target.endpoints());
        }
    }

    static final class OutboundTargetDecorator
            implements Prototype.BuilderDecorator<OidcOutboundTargetConfig.BuilderBase<?, ?>> {
        @Override
        public void decorate(OidcOutboundTargetConfig.BuilderBase<?, ?> target) {
            if (target.tokenPropagationEnabled() && target.clientCredentialsGrantEnabled()) {
                throw new IllegalArgumentException(
                        "Token Propagation and Client Credentials Grant cannot both be enabled on the same outbound target");
            }
        }
    }

    static final class TenantResolutionDecorator
            implements Prototype.BuilderDecorator<OidcTenantResolutionConfig.BuilderBase<?, ?>> {
        @Override
        public void decorate(OidcTenantResolutionConfig.BuilderBase<?, ?> target) {
            target.headerName()
                    .filter(headerName -> headerName.isBlank() || !headerName.equals(headerName.strip()))
                    .ifPresent(ignored -> {
                        throw new IllegalArgumentException("tenant-resolution.header-name must not be blank or padded");
                    });
            target.pathSegment()
                    .filter(pathSegment -> pathSegment < 0)
                    .ifPresent(ignored -> {
                        throw new IllegalArgumentException("tenant-resolution.path-segment must not be negative");
                    });
            target.pathTemplate().ifPresent(pathTemplate -> {
                if (pathTemplate.isBlank() || !pathTemplate.equals(pathTemplate.strip())) {
                    throw new IllegalArgumentException("tenant-resolution.path-template must not be blank or padded");
                }
                validateSingleTenantVariable(pathTemplate, "tenant-resolution.path-template");
                if (!pathTemplateSegments(pathTemplate).contains(TENANT_VARIABLE)) {
                    throw new IllegalArgumentException(
                            "tenant-resolution.path-template must contain {tenant} as a complete path segment");
                }
            });
            target.hostTemplate().ifPresent(hostTemplate -> {
                if (hostTemplate.isBlank() || !hostTemplate.equals(hostTemplate.strip())) {
                    throw new IllegalArgumentException("tenant-resolution.host-template must not be blank or padded");
                }
                validateSingleTenantVariable(hostTemplate, "tenant-resolution.host-template");
            });
        }
    }

    private static void validateSingleTenantVariable(String template, String configKey) {
        int variableIndex = template.indexOf(TENANT_VARIABLE);
        if (variableIndex == -1
                || template.indexOf(TENANT_VARIABLE, variableIndex + TENANT_VARIABLE.length()) != -1) {
            throw new IllegalArgumentException(configKey + " must contain exactly one {tenant} placeholder");
        }
    }

    private static List<String> pathTemplateSegments(String pathTemplate) {
        return Arrays.stream(pathTemplate.split("/"))
                .filter(segment -> !segment.isEmpty())
                .toList();
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
         * Quotes: "MUST contain the `openid` scope value";
         * "OAuth 2.0 Client Identifier valid at the Authorization Server";
         * "Redirection URI to which the response will be sent".
         */
        tenant.clientId()
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-id must be configured when Authorization Code Flow is enabled"));
        validateTokenEndpointAuthentication(tenant, false, "Authorization Code Flow");
        boolean tokenEndpointTlsRequired = endpoints.tlsRequired()
                || mutualTlsTokenEndpointAuthentication(tenant.clientSecret(),
                                                        tenant.tokenEndpointAuthenticationMethod());
        URI redirectionEndpointUri = authorizationCode.redirectionEndpointUri()
                .orElseThrow(() -> new IllegalArgumentException(
                        "redirection-endpoint-uri must be configured when Authorization Code Flow is enabled"));
        validateRedirectionEndpointUri(redirectionEndpointUri, endpoints.tlsRequired());
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        requireEndpointOrWellKnown(endpoints.authorizationEndpointUri(),
                                   wellKnownUri,
                                   "authorization-endpoint-uri",
                                   "Authorization Code Flow",
                                   endpoints.tlsRequired(),
                                   OidcConfigSupport::validateAuthorizationEndpointUri);
        requireEndpointOrWellKnown(endpoints.tokenEndpointUri(),
                                   wellKnownUri,
                                   "token-endpoint-uri",
                                   "Authorization Code Flow",
                                   tokenEndpointTlsRequired,
                                   tokenEndpointTlsRequired,
                                   OidcConfigSupport::validateTokenEndpointUri);
        tenant.issuer()
                .or(endpoints::wellKnownUri)
                .orElseThrow(() -> new IllegalArgumentException(
                        "issuer or well-known-uri must be configured when Authorization Code Flow is enabled"));
        if (!authorizationCode.scopes().contains("openid")) {
            throw new IllegalArgumentException(
                    "openid scope must be configured when Authorization Code Flow is enabled");
        }
        tenant.cookies()
                .encryptionSecret()
                .orElseThrow(() -> new IllegalArgumentException(
                        "cookies.encryption-secret must be configured when Authorization Code Flow is enabled"));
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

        configuredAuthorizationCode
                .filter(OidcAuthorizationCodeConfig::enabled)
                .orElseThrow(() -> new IllegalArgumentException(
                        "authorization-code must be configured when UserInfo is enabled"));
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        requireEndpointOrWellKnown(endpoints.userInfoEndpointUri(),
                                   wellKnownUri,
                                   "user-info-endpoint-uri",
                                   "UserInfo",
                                   endpoints.tlsRequired(),
                                   OidcConfigSupport::validateUserInfoEndpointUri);
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
        validateLocalEndpointUri("local-endpoint-uri", logout.localEndpointUri());
        configuredAuthorizationCode
                .filter(OidcAuthorizationCodeConfig::enabled)
                .flatMap(OidcAuthorizationCodeConfig::redirectionEndpointUri)
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
        requireEndpointOrWellKnown(endpoints.endSessionEndpointUri(),
                                   wellKnownUri,
                                   "end-session-endpoint-uri",
                                   "RP-Initiated Logout",
                                   endpoints.tlsRequired(),
                                   OidcConfigSupport::validateEndSessionEndpointUri);
        endSession.postLogoutRedirectUri()
                .ifPresent(uri -> validatePostLogoutRedirectUri("post-logout-redirect-uri",
                                                                uri,
                                                                endpoints.tlsRequired()));
        endSession.allowedPostLogoutRedirectUris()
                .forEach(uri -> validatePostLogoutRedirectUri("allowed-post-logout-redirect-uris",
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
        case JWT -> {
            tenant.issuer()
                    .or(() -> endpoints.wellKnownUri())
                    .orElseThrow(() -> new IllegalArgumentException(
                            "issuer or well-known-uri must be configured when JWT access-token validation is enabled"));
            Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
            requireEndpointOrWellKnown(endpoints.jwksUri(),
                                       wellKnownUri,
                                       "jwks-uri",
                                       "JWT access-token validation",
                                       endpoints.tlsRequired(),
                                       OidcConfigSupport::validateJwksUri);
            if (tokenValidation.audienceValidationEnabled()) {
                /*
                 * Spec: RFC 7519, 4.1.3 "aud" (Audience) Claim
                 * https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
                 * Quote: "then the JWT MUST be rejected".
                 */
                tokenValidation.audience()
                        .orElseThrow(() -> new IllegalArgumentException(
                                "token-validation.audience must be configured when JWT access-token validation "
                                        + "is enabled"));
            }
        }
        case INTROSPECTION -> {
            /*
             * Spec: RFC 7662, 2.1 Introspection Request
             * https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1
             * Quote: "MUST also require some form of authorization".
             */
            Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
            requireEndpointOrWellKnown(endpoints.introspectionEndpointUri(),
                                       wellKnownUri,
                                       "introspection-endpoint-uri",
                                       "introspection",
                                       endpoints.tlsRequired(),
                                       OidcConfigSupport::validateIntrospectionEndpointUri);
            tenant.clientId()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "client-id must be configured when introspection is enabled"));
            tenant.clientSecret()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "client-secret must be configured when introspection is enabled"));
            if (tokenValidation.audienceValidationEnabled()) {
                tokenValidation.audience()
                        .orElseThrow(() -> new IllegalArgumentException(
                                "token-validation.audience must be configured when introspection is enabled"));
            }
        }
        default -> throw new IllegalStateException("Unexpected token validation method: " + method);
        }
    }

    private static void validateOutbound(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                         OidcOutboundConfig outbound,
                                         OidcEndpointConfig endpoints) {
        if (outbound.tokenPropagationEnabled() && outbound.clientCredentialsGrantEnabled()) {
            throw new IllegalArgumentException(
                    "Token Propagation and Client Credentials Grant cannot both be enabled without target selection");
        }

        if (!outbound.clientCredentialsGrantEnabled()) {
            return;
        }

        validateClientCredentialsGrant(tenant, endpoints, "Client Credentials Grant");
    }

    static void validateClientCredentialsGrant(OidcTenantConfig tenant,
                                               OidcEndpointConfig endpoints,
                                               String operation) {
        validateClientCredentialsGrant(tenant.clientId(),
                                       tenant.clientSecret(),
                                       tenant.tokenEndpointAuthenticationMethod(),
                                       tenant.clientAssertion(),
                                       tenant.webClient(),
                                       tenant.issuer(),
                                       endpoints,
                                       operation);
    }

    private static void validateClientCredentialsGrant(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                       OidcEndpointConfig endpoints,
                                                       String operation) {
        validateClientCredentialsGrant(tenant.clientId(),
                                       tenant.clientSecret(),
                                       tenant.tokenEndpointAuthenticationMethod(),
                                       tenant.clientAssertion(),
                                       tenant.webClient(),
                                       tenant.issuer(),
                                       endpoints,
                                       operation);
    }

    private static void validateClientCredentialsGrant(Optional<String> clientId,
                                                       Optional<String> clientSecret,
                                                       Optional<OidcClientAuthenticationMethod> authenticationMethod,
                                                       OidcClientAssertionConfig clientAssertion,
                                                       WebClientConfig webClient,
                                                       Optional<URI> issuer,
                                                       OidcEndpointConfig endpoints,
                                                       String operation) {
        /*
         * Spec: RFC 6749, 4.4 Client Credentials Grant and 4.4.2 Access Token Request
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.2
         * Quotes: "MUST only be used by confidential clients"; "client MUST authenticate".
         */
        clientId.orElseThrow(() -> new IllegalArgumentException(
                "client-id must be configured when " + operation + " is enabled"));
        validateTokenEndpointAuthentication(clientSecret,
                                            authenticationMethod,
                                            clientAssertion,
                                            webClient,
                                            true,
                                            operation);
        boolean tokenEndpointTlsRequired = endpoints.tlsRequired()
                || mutualTlsTokenEndpointAuthentication(clientSecret, authenticationMethod);
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(issuer, endpoints);
        requireEndpointOrWellKnown(endpoints.tokenEndpointUri(),
                                   wellKnownUri,
                                   "token-endpoint-uri",
                                   operation,
                                   tokenEndpointTlsRequired,
                                   tokenEndpointTlsRequired,
                                   OidcConfigSupport::validateTokenEndpointUri);
    }

    private static void requireEndpointOrWellKnown(Optional<URI> endpointUri,
                                                   Optional<URI> wellKnownUri,
                                                   String endpointConfigKey,
                                                   String operation,
                                                   boolean tlsRequired,
                                                   EndpointUriValidator endpointValidator) {
        requireEndpointOrWellKnown(endpointUri,
                                   wellKnownUri,
                                   endpointConfigKey,
                                   operation,
                                   tlsRequired,
                                   tlsRequired,
                                   endpointValidator);
    }

    private static void requireEndpointOrWellKnown(Optional<URI> endpointUri,
                                                   Optional<URI> wellKnownUri,
                                                   String endpointConfigKey,
                                                   String operation,
                                                   boolean endpointTlsRequired,
                                                   boolean wellKnownTlsRequired,
                                                   EndpointUriValidator endpointValidator) {
        endpointUri
                .or(() -> wellKnownUri)
                .orElseThrow(() -> new IllegalArgumentException(
                        endpointConfigKey + " or well-known-uri must be configured when " + operation + " is enabled"));
        endpointUri.ifPresent(uri -> endpointValidator.validate(uri, endpointTlsRequired));
        if (endpointUri.isEmpty()) {
            wellKnownUri.ifPresent(uri -> validateWellKnownUri(uri, wellKnownTlsRequired));
        }
    }

    static void validateAuthorizationEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme".
         *
         * Spec: RFC 6749, 3.1 Authorization Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
         * Quote: "The endpoint URI MUST NOT include a fragment component".
         */
        validateHttpsEndpointUri("authorization-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("authorization-endpoint-uri", uri);
    }

    static void validateIssuerUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quotes: "URL using the `https` scheme"; "no query or fragment components".
         */
        validateHttpsEndpointUri("issuer", uri, tlsRequired, false);
        validateNoQuery("issuer", uri);
        validateNoFragment("issuer", uri);
    }

    private static void validateRedirectionEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 6749, 3.1.2 Redirection Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1.2
         * Quotes: "MUST be an absolute URI"; "MUST NOT include a fragment component".
         */
        if (!uri.isAbsolute()) {
            throw new IllegalArgumentException("redirection-endpoint-uri must be an absolute URI: " + uri);
        }
        validateHttpsEndpointUri("redirection-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("redirection-endpoint-uri", uri);
    }

    static void validateJwksUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme".
         */
        validateHttpsEndpointUri("jwks-uri", uri, tlsRequired, true);
    }

    static void validateEndSessionEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect RP-Initiated Logout 1.0, 2.1 OpenID Provider Discovery Metadata
         * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
         * Quotes: "URL at the OP to which an RP can perform a redirect to request that the End-User be logged out";
         * "This URL MUST use the `https` scheme"; "MAY contain port, path, and query parameter components".
         */
        validateHttpsEndpointUri("end-session-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("end-session-endpoint-uri", uri);
    }

    static void validateUserInfoEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme".
         */
        validateHttpsEndpointUri("user-info-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("user-info-endpoint-uri", uri);
    }

    private static void validatePostLogoutRedirectUri(String configKey, URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect RP-Initiated Logout 1.0, 2 RP-Initiated Logout
         * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
         * Quotes: "`post_logout_redirect_uri` value MUST have been previously registered with the OP";
         * "This URI SHOULD use the `https` scheme".
         */
        validateHttpsEndpointUri(configKey, uri, tlsRequired, false);
        validateNoFragment(configKey, uri);
    }

    private static void validateWellKnownUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme".
         */
        validateHttpsEndpointUri("well-known-uri", uri, tlsRequired, false);
    }

    static void validateTokenEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 6749, 3.2 Token Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
         * Quotes: "The authorization server MUST require the use of TLS"; "MUST NOT include a fragment component".
         */
        validateHttpsEndpointUri("token-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("token-endpoint-uri", uri);
    }

    static void validateIntrospectionEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 7662, 2 Introspection Endpoint
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-2
         * Quote: "MUST be protected by a transport-layer security mechanism".
         */
        validateHttpsEndpointUri("introspection-endpoint-uri", uri, tlsRequired, false);
    }

    private static void validateHttpsEndpointUri(String configKey, URI uri, boolean tlsRequired, boolean fileAllowed) {
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException(configKey + " must define a URI scheme");
        }
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        if (!tlsRequired && ("http".equalsIgnoreCase(scheme) || fileAllowed && "file".equalsIgnoreCase(scheme))) {
            return;
        }
        throw new IllegalArgumentException(
                configKey + " must use https unless endpoints.tls-required is disabled: " + uri);
    }

    private static void validateNoFragment(String configKey, URI uri) {
        if (uri.getRawFragment() != null) {
            throw new IllegalArgumentException(configKey + " must not include a fragment component: " + uri);
        }
    }

    private static void validateNoQuery(String configKey, URI uri) {
        if (uri.getRawQuery() != null) {
            throw new IllegalArgumentException(configKey + " must not include a query component: " + uri);
        }
    }

    private static void validateLocalEndpointUri(String configKey, URI uri) {
        if (uri.getScheme() != null || uri.getRawAuthority() != null) {
            throw new IllegalArgumentException(configKey + " must be a local absolute path: " + uri);
        }
        String path = uri.getPath();
        if (path == null || path.isEmpty() || !path.startsWith("/")) {
            throw new IllegalArgumentException(configKey + " must be a local absolute path: " + uri);
        }
        if (uri.getRawQuery() != null) {
            throw new IllegalArgumentException(configKey + " must not include a query component: " + uri);
        }
        validateNoFragment(configKey, uri);
    }

    private static void validateTokenEndpointAuthentication(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                            boolean confidentialClientRequired,
                                                            String operation) {
        validateTokenEndpointAuthentication(tenant.clientSecret(),
                                            tenant.tokenEndpointAuthenticationMethod(),
                                            tenant.clientAssertion(),
                                            tenant.webClient(),
                                            confidentialClientRequired,
                                            operation);
    }

    private static void validateTokenEndpointAuthentication(Optional<String> clientSecret,
                                                            Optional<OidcClientAuthenticationMethod> authenticationMethod,
                                                            OidcClientAssertionConfig clientAssertion,
                                                            WebClientConfig webClient,
                                                            boolean confidentialClientRequired,
                                                            String operation) {
        OidcClientAuthenticationMethod method = authenticationMethod
                .orElseGet(() -> clientSecret
                        .isPresent()
                        ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        : OidcClientAuthenticationMethod.NONE);
        switch (method) {
        case CLIENT_SECRET_BASIC, CLIENT_SECRET_POST -> clientSecret
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-secret must be configured for " + method
                                + " Token Endpoint authentication when " + operation + " is enabled"));
        case CLIENT_SECRET_JWT -> {
            clientSecret.orElseThrow(() -> new IllegalArgumentException(
                    "client-secret must be configured for CLIENT_SECRET_JWT Token Endpoint authentication when "
                            + operation + " is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.CLIENT_SECRET_JWT,
                                             operation);
        }
        case PRIVATE_KEY_JWT -> {
            clientAssertion.jwk()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "client-assertion.jwk must be configured for PRIVATE_KEY_JWT Token Endpoint authentication "
                                    + "when " + operation + " is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                             operation);
        }
        case TLS_CLIENT_AUTH, SELF_SIGNED_TLS_CLIENT_AUTH -> {
            validateMutualTlsClientAuthentication(webClient, method, operation);
        }
        case NONE -> {
            if (confidentialClientRequired) {
                throw new IllegalArgumentException(
                        "Token Endpoint authentication cannot be NONE when " + operation + " is enabled");
            }
        }
        default -> throw new IllegalStateException("Unexpected client authentication method: " + method);
        }
    }

    private static void validateMutualTlsClientAuthentication(WebClientConfig webClient,
                                                              OidcClientAuthenticationMethod method,
                                                              String operation) {
        TlsConfig tls = webClient.tls().prototype();
        /*
         * Spec: RFC 8705, 2 Mutual TLS for OAuth Client Authentication
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-2
         * Quote: "the TLS connection between the client and the authorization server MUST have been established or
         * re-established with mutual-TLS X.509 certificate authentication".
         */
        if (tls.enabled()
                && (tls.sslContext().isPresent()
                        || tls.privateKey().isPresent() && !tls.privateKeyCertChain().isEmpty()
                        || !(tls.manager() instanceof ConfiguredTlsManager))) {
            return;
        }
        throw new IllegalArgumentException(
                "webclient.tls must be enabled and private-key plus certificate chain, ssl-context, or custom manager "
                        + "must be configured for " + method + " Token Endpoint authentication when " + operation
                        + " is enabled");
    }

    private static boolean mutualTlsTokenEndpointAuthentication(Optional<String> clientSecret,
                                                               Optional<OidcClientAuthenticationMethod> authenticationMethod) {
        OidcClientAuthenticationMethod method = authenticationMethod
                .orElseGet(() -> clientSecret
                        .isPresent()
                        ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        : OidcClientAuthenticationMethod.NONE);
        return method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
    }

    private static void validateClientAssertion(OidcClientAssertionConfig clientAssertion) {
        if (clientAssertion.lifetime().isZero() || clientAssertion.lifetime().isNegative()) {
            throw new IllegalArgumentException("client-assertion.lifetime must be positive");
        }
        clientAssertion.algorithm()
                .filter(algorithm -> algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip())
                        || "none".equalsIgnoreCase(algorithm))
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException(
                            "client-assertion.algorithm must not be blank, padded, or none");
                });
        clientAssertion.keyId()
                .filter(keyId -> keyId.isBlank() || !keyId.equals(keyId.strip()))
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException("client-assertion.key-id must not be blank or padded");
                });
    }

    private static void validateClientAssertionAlgorithm(OidcClientAssertionConfig clientAssertion,
                                                         OidcClientAuthenticationMethod method,
                                                         String operation) {
        clientAssertion.algorithm()
                .filter(algorithm -> switch (method) {
                case CLIENT_SECRET_JWT -> !OidcClientAuthenticationSupport.isClientSecretJwtAlgorithm(algorithm);
                case PRIVATE_KEY_JWT -> !OidcClientAuthenticationSupport.isPrivateKeyJwtAlgorithm(algorithm);
                default -> false;
                })
                .ifPresent(algorithm -> {
                    String algorithms = switch (method) {
                    case CLIENT_SECRET_JWT -> OidcClientAuthenticationSupport.clientSecretJwtAlgorithms();
                    case PRIVATE_KEY_JWT -> OidcClientAuthenticationSupport.privateKeyJwtAlgorithms();
                    default -> throw new IllegalStateException(
                            "Unexpected client assertion authentication method: " + method);
                    };
                    throw new IllegalArgumentException("client-assertion.algorithm must be one of "
                                                               + algorithms
                                                               + " for " + method
                                                               + " Token Endpoint authentication when "
                                                               + operation + " is enabled");
                });
    }

    @FunctionalInterface
    private interface EndpointUriValidator {
        void validate(URI uri, boolean tlsRequired);
    }
}
