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
            target.headerName().ifPresent(headerName -> require(!headerName.isBlank() && headerName.equals(headerName.strip()),
                                                                "tenant-resolution.header-name must not be blank or padded"));
            target.pathSegment().ifPresent(pathSegment -> require(pathSegment >= 0,
                                                                  "tenant-resolution.path-segment must not be negative"));
            target.pathTemplate().ifPresent(pathTemplate -> {
                require(!pathTemplate.isBlank() && pathTemplate.equals(pathTemplate.strip()),
                        "tenant-resolution.path-template must not be blank or padded");
                validateSingleTenantVariable(pathTemplate, "tenant-resolution.path-template");
                require(pathTemplateSegments(pathTemplate).contains(TENANT_VARIABLE),
                        "tenant-resolution.path-template must contain {tenant} as a complete path segment");
            });
            target.hostTemplate().ifPresent(hostTemplate -> {
                require(!hostTemplate.isBlank() && hostTemplate.equals(hostTemplate.strip()),
                        "tenant-resolution.host-template must not be blank or padded");
                validateSingleTenantVariable(hostTemplate, "tenant-resolution.host-template");
            });
        }
    }

    private static void validateSingleTenantVariable(String template, String configKey) {
        int variableIndex = template.indexOf(TENANT_VARIABLE);
        require(variableIndex != -1, configKey + " must contain exactly one {tenant} placeholder");
        require(template.indexOf(TENANT_VARIABLE, variableIndex + TENANT_VARIABLE.length()) == -1,
                configKey + " must contain exactly one {tenant} placeholder");
    }

    private static java.util.List<String> pathTemplateSegments(String pathTemplate) {
        return java.util.Arrays.stream(pathTemplate.split("/"))
                .filter(segment -> !segment.isEmpty())
                .toList();
    }

    private static void validateAuthorizationCode(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                  OidcAuthorizationCodeConfig authorizationCode,
                                                  OidcEndpointConfig endpoints) {
        if (!authorizationCode.enabled()) {
            return;
        }

        require(tenant.clientId().isPresent(), "client-id must be configured when Authorization Code Flow is enabled");
        require(authorizationCode.redirectionEndpointUri().isPresent(),
                "redirection-endpoint-uri must be configured when Authorization Code Flow is enabled");
        require(endpoints.authorizationEndpointUri().isPresent() || endpoints.discoveryUri().isPresent(),
                "authorization-endpoint-uri or discovery-uri must be configured when Authorization Code Flow is enabled");
        require(endpoints.tokenEndpointUri().isPresent() || endpoints.discoveryUri().isPresent(),
                "token-endpoint-uri or discovery-uri must be configured when Authorization Code Flow is enabled");
        require(tenant.issuer().isPresent() || endpoints.discoveryUri().isPresent(),
                "issuer or discovery-uri must be configured when Authorization Code Flow is enabled");
        require(authorizationCode.scopes().contains("openid"),
                "openid scope must be configured when Authorization Code Flow is enabled");
    }

    private static void validateProtectedResource(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                  OidcProtectedResourceConfig protectedResource,
                                                  OidcTokenTransportConfig tokenTransport,
                                                  OidcEndpointConfig endpoints) {
        if (!protectedResource.enabled()) {
            return;
        }

        OidcTokenValidationConfig tokenValidation = protectedResource.tokenValidation();
        require(tokenTransport.authorizationHeaderEnabled()
                        || tokenTransport.queryParameterEnabled(),
                "at least one Bearer Token transport must be enabled when Protected Resource is enabled");
        require(tokenValidation.method().isPresent(),
                "token-validation.method must be configured when Protected Resource is enabled");

        tokenValidation.method().ifPresent(method -> {
            switch (method) {
            case JWT -> {
                require(tenant.issuer().isPresent(),
                        "issuer must be configured when JWT access-token validation is enabled");
                require(endpoints.jwksUri().isPresent(),
                        "jwks-uri must be configured when JWT access-token validation is enabled");
                endpoints.jwksUri().ifPresent(OidcJwkSetLoader::validateJwkSetUri);
                if (tokenValidation.audienceValidationEnabled()) {
                    require(tokenValidation.audience().isPresent(),
                            "token-validation.audience must be configured when JWT access-token validation is enabled");
                }
            }
            case INTROSPECTION -> {
                require(endpoints.introspectionEndpointUri().isPresent() || endpoints.discoveryUri().isPresent(),
                        "introspection-endpoint-uri or discovery-uri must be configured when introspection is enabled");
                require(tenant.clientId().isPresent(),
                        "client-id must be configured when introspection is enabled");
                require(tenant.clientSecret().isPresent(),
                        "client-secret must be configured when introspection is enabled");
            }
            default -> throw new IllegalStateException("Unexpected token validation method: " + method);
            }
        });
    }

    private static void validateOutbound(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                         OidcOutboundConfig outbound,
                                         OidcEndpointConfig endpoints) {
        require(!(outbound.tokenPropagationEnabled() && outbound.clientCredentialsGrantEnabled()),
                "Token Propagation and Client Credentials Grant cannot both be enabled without target selection");

        if (!outbound.clientCredentialsGrantEnabled()) {
            return;
        }

        require(tenant.clientId().isPresent(),
                "client-id must be configured when Client Credentials Grant is enabled");
        require(tenant.clientSecret().isPresent(),
                "client-secret must be configured when Client Credentials Grant is enabled");
        require(endpoints.tokenEndpointUri().isPresent() || endpoints.discoveryUri().isPresent(),
                "token-endpoint-uri or discovery-uri must be configured when Client Credentials Grant is enabled");
    }

    private static void require(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }
}
