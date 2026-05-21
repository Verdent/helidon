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

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Prototype;

final class OidcConfigSupport {
    private static final String TENANT_VARIABLE = "{tenant}";

    private OidcConfigSupport() {
    }

    private static Optional<OidcEndpointPolicy> endpointPolicy(OidcProtectedResourceConfig protectedResource,
                                                               OidcAuthorizationCodeConfig authorizationCode) {
        boolean bearerTokenAuthentication = protectedResource.enabled();
        boolean authorizationCodeFlow = authorizationCode.enabled();

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

    static Optional<OidcEndpointPolicy> endpointPolicy(OidcTenantConfig tenant) {
        return endpointPolicy(tenant.protectedResource(), tenant.authorizationCode());
    }

    private static Optional<OidcOutboundPolicy> outboundPolicy(OidcOutboundConfig outbound) {
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

    static Optional<OidcOutboundPolicy> outboundPolicy(OidcTenantConfig tenant) {
        return outboundPolicy(tenant.outbound());
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

    private static void validateAuthorizationCode(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                  OidcAuthorizationCodeConfig authorizationCode,
                                                  OidcEndpointConfig endpoints) {
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
        authorizationCode.redirectionEndpointUri()
                .orElseThrow(() -> new IllegalArgumentException(
                        "redirection-endpoint-uri must be configured when Authorization Code Flow is enabled"));
        endpoints.authorizationEndpointUri()
                .or(() -> endpoints.discoveryUri())
                .orElseThrow(() -> new IllegalArgumentException(
                        "authorization-endpoint-uri or discovery-uri must be configured when Authorization Code Flow "
                                + "is enabled"));
        endpoints.tokenEndpointUri()
                .or(() -> endpoints.discoveryUri())
                .orElseThrow(() -> new IllegalArgumentException(
                        "token-endpoint-uri or discovery-uri must be configured when Authorization Code Flow "
                                + "is enabled"));
        tenant.issuer()
                .or(() -> endpoints.discoveryUri())
                .orElseThrow(() -> new IllegalArgumentException(
                        "issuer or discovery-uri must be configured when Authorization Code Flow is enabled"));
        if (!authorizationCode.scopes().contains("openid")) {
            throw new IllegalArgumentException(
                    "openid scope must be configured when Authorization Code Flow is enabled");
        }
    }

    private static void validateProtectedResource(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                  OidcProtectedResourceConfig protectedResource,
                                                  OidcTokenTransportConfig tokenTransport,
                                                  OidcEndpointConfig endpoints) {
        if (!protectedResource.enabled()) {
            return;
        }

        OidcTokenValidationConfig tokenValidation = protectedResource.tokenValidation();
        if (!tokenTransport.authorizationHeaderEnabled() && !tokenTransport.queryParameterEnabled()) {
            throw new IllegalArgumentException(
                    "at least one Bearer Token transport must be enabled when Protected Resource is enabled");
        }
        OidcTokenValidationMethod method = tokenValidation.method()
                .orElseThrow(() -> new IllegalArgumentException(
                        "token-validation.method must be configured when Protected Resource is enabled"));

        switch (method) {
        case JWT -> {
            tenant.issuer()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "issuer must be configured when JWT access-token validation is enabled"));
            endpoints.jwksUri()
                    .map(jwksUri -> {
                        OidcJwkSetLoader.validateJwkSetUri(jwksUri);
                        return jwksUri;
                    })
                    .orElseThrow(() -> new IllegalArgumentException(
                            "jwks-uri must be configured when JWT access-token validation is enabled"));
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
            endpoints.introspectionEndpointUri()
                    .map(introspectionEndpointUri -> {
                        OidcIntrospectionAccessTokenValidator
                                .validateIntrospectionEndpointUri(introspectionEndpointUri);
                        return introspectionEndpointUri;
                    })
                    .orElseThrow(() -> new IllegalArgumentException(
                            "introspection-endpoint-uri must be configured when introspection is enabled"));
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
        tenant.clientSecret()
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-secret must be configured when Client Credentials Grant is enabled"));
        endpoints.tokenEndpointUri()
                .or(() -> endpoints.discoveryUri())
                .orElseThrow(() -> new IllegalArgumentException(
                        "token-endpoint-uri or discovery-uri must be configured when Client Credentials Grant "
                                + "is enabled"));
    }
}
