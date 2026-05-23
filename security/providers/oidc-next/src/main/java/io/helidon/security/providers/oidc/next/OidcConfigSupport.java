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
import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Prototype;

final class OidcConfigSupport {
    private static final String TENANT_VARIABLE = "{tenant}";

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
            validateAuthorizationCode(target, target.authorizationCode(), target.endpoints());
            validateProtectedResource(target, target.protectedResource(), target.tokenTransport(), target.endpoints());
            validateOutbound(target, target.outbound(), target.endpoints());
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
        authorizationCode.redirectionEndpointUri()
                .orElseThrow(() -> new IllegalArgumentException(
                        "redirection-endpoint-uri must be configured when Authorization Code Flow is enabled"));
        Optional<URI> authorizationEndpointUri = endpoints.authorizationEndpointUri();
        Optional<URI> discoveryUri = OidcProviderMetadata.discoveryUri(tenant.issuer(), endpoints);
        authorizationEndpointUri
                .or(() -> discoveryUri)
                .orElseThrow(() -> new IllegalArgumentException(
                        "authorization-endpoint-uri or discovery-uri must be configured when Authorization Code Flow "
                                + "is enabled"));
        authorizationEndpointUri.ifPresent(uri -> validateAuthorizationEndpointUri(uri, endpoints.tlsRequired()));
        Optional<URI> tokenEndpointUri = endpoints.tokenEndpointUri();
        tokenEndpointUri
                .or(() -> discoveryUri)
                .orElseThrow(() -> new IllegalArgumentException(
                        "token-endpoint-uri or discovery-uri must be configured when Authorization Code Flow "
                                + "is enabled"));
        tokenEndpointUri.ifPresent(uri -> validateTokenEndpointUri(uri, endpoints.tlsRequired()));
        if (authorizationEndpointUri.isEmpty() || tokenEndpointUri.isEmpty()) {
            discoveryUri.ifPresent(uri -> validateDiscoveryUri(uri, endpoints.tlsRequired()));
        }
        tenant.issuer()
                .or(endpoints::discoveryUri)
                .orElseThrow(() -> new IllegalArgumentException(
                        "issuer or discovery-uri must be configured when Authorization Code Flow is enabled"));
        if (!authorizationCode.scopes().contains("openid")) {
            throw new IllegalArgumentException(
                    "openid scope must be configured when Authorization Code Flow is enabled");
        }
        tenant.cookies()
                .encryptionSecret()
                .orElseThrow(() -> new IllegalArgumentException(
                        "cookies.encryption-secret must be configured when Authorization Code Flow is enabled"));
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
                    .or(() -> endpoints.discoveryUri())
                    .orElseThrow(() -> new IllegalArgumentException(
                            "issuer or discovery-uri must be configured when JWT access-token validation is enabled"));
            Optional<URI> discoveryUri = OidcProviderMetadata.discoveryUri(tenant.issuer(), endpoints);
            Optional<URI> jwksUri = endpoints.jwksUri();
            jwksUri
                    .or(() -> discoveryUri)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "jwks-uri or discovery-uri must be configured when JWT access-token validation is enabled"));
            jwksUri.ifPresent(uri -> validateJwksUri(uri, endpoints.tlsRequired()));
            if (jwksUri.isEmpty()) {
                discoveryUri.ifPresent(uri -> validateDiscoveryUri(uri, endpoints.tlsRequired()));
            }
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
            URI introspectionEndpointUri = endpoints.introspectionEndpointUri()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "introspection-endpoint-uri must be configured when introspection is enabled"));
            validateIntrospectionEndpointUri(introspectionEndpointUri, endpoints.tlsRequired());
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

        /*
         * Spec: RFC 6749, 4.4 Client Credentials Grant and 4.4.2 Access Token Request
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.2
         * Quotes: "MUST only be used by confidential clients"; "client MUST authenticate".
         */
        tenant.clientId()
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-id must be configured when Client Credentials Grant is enabled"));
        validateTokenEndpointAuthentication(tenant, true, "Client Credentials Grant");
        Optional<URI> discoveryUri = OidcProviderMetadata.discoveryUri(tenant.issuer(), endpoints);
        Optional<URI> tokenEndpointUri = endpoints.tokenEndpointUri();
        tokenEndpointUri
                .or(() -> discoveryUri)
                .orElseThrow(() -> new IllegalArgumentException(
                        "token-endpoint-uri or discovery-uri must be configured when Client Credentials Grant "
                                + "is enabled"));
        tokenEndpointUri.ifPresent(uri -> validateTokenEndpointUri(uri, endpoints.tlsRequired()));
        if (tokenEndpointUri.isEmpty()) {
            discoveryUri.ifPresent(uri -> validateDiscoveryUri(uri, endpoints.tlsRequired()));
        }
    }

    private static void validateAuthorizationEndpointUri(URI uri, boolean tlsRequired) {
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

    static void validateJwksUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme".
         */
        validateHttpsEndpointUri("jwks-uri", uri, tlsRequired, true);
    }

    private static void validateDiscoveryUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme".
         */
        validateHttpsEndpointUri("discovery-uri", uri, tlsRequired, false);
    }

    private static void validateTokenEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 6749, 3.2 Token Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
         * Quotes: "The authorization server MUST require the use of TLS"; "MUST NOT include a fragment component".
         */
        validateHttpsEndpointUri("token-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("token-endpoint-uri", uri);
    }

    private static void validateIntrospectionEndpointUri(URI uri, boolean tlsRequired) {
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

    private static void validateTokenEndpointAuthentication(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                            boolean confidentialClientRequired,
                                                            String operation) {
        OidcClientAuthenticationMethod method = tenant.tokenEndpointAuthenticationMethod()
                .orElseGet(() -> tenant.clientSecret()
                        .isPresent()
                        ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        : OidcClientAuthenticationMethod.NONE);
        switch (method) {
        case CLIENT_SECRET_BASIC, CLIENT_SECRET_POST -> tenant.clientSecret()
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-secret must be configured for " + method
                                + " Token Endpoint authentication when " + operation + " is enabled"));
        case NONE -> {
            if (confidentialClientRequired) {
                throw new IllegalArgumentException(
                        "Token Endpoint authentication cannot be NONE when " + operation + " is enabled");
            }
        }
        default -> throw new IllegalStateException("Unexpected client authentication method: " + method);
        }
    }
}
