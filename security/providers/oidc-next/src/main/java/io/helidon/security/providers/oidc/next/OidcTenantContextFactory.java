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

final class OidcTenantContextFactory {
    private final TenantInitializer initializer;

    private OidcTenantContextFactory(TenantInitializer initializer) {
        this.initializer = initializer;
    }

    static OidcTenantContextFactory create() {
        return create(defaultInitializer(OidcProviderMetadataLoader.create()));
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

    private static TenantInitializer defaultInitializer(OidcProviderMetadataLoader metadataLoader) {
        return (tenantId, tenantConfig) -> {
            try {
                OidcProviderMetadata staticMetadata = OidcProviderMetadata.fromStaticConfig(tenantConfig);
                OidcProviderMetadata metadata = needsDiscovery(tenantConfig, staticMetadata)
                        ? metadataLoader.load(staticMetadata)
                        : staticMetadata;
                validateJwtMetadata(tenantConfig, metadata);
                return OidcTenantContext.ready(tenantId, tenantConfig, metadata);
            } catch (RuntimeException e) {
                return OidcTenantContext.failed(tenantId, tenantConfig);
            }
        };
    }

    private static boolean needsDiscovery(OidcTenantConfig tenantConfig, OidcProviderMetadata staticMetadata) {
        if (staticMetadata.discoveryUri().isEmpty()) {
            return false;
        }
        OidcTokenValidationConfig tokenValidation = tenantConfig.protectedResource().tokenValidation();
        if (tokenValidation.method().filter(OidcTokenValidationMethod.JWT::equals).isPresent()
                && (staticMetadata.issuer().isEmpty() || staticMetadata.jwkSetUri().isEmpty())) {
            return true;
        }
        OidcAuthorizationCodeConfig authorizationCode = tenantConfig.authorizationCode();
        if (authorizationCode.enabled()
                && (staticMetadata.authorizationEndpointUri().isEmpty()
                || staticMetadata.tokenEndpointUri().isEmpty())) {
            return true;
        }
        return tenantConfig.outbound().clientCredentialsGrantEnabled()
                && staticMetadata.tokenEndpointUri().isEmpty();
    }

    private static void validateJwtMetadata(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        OidcTokenValidationConfig tokenValidation = tenantConfig.protectedResource().tokenValidation();
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
                                             "discovered jwks_uri must be present for JWT access-token validation");
                                 });
    }

    @FunctionalInterface
    interface TenantInitializer {
        OidcTenantContext initialize(String tenantId, OidcTenantConfig tenantConfig);
    }
}
