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

final class OidcTenantContext {
    private final String tenantId;
    private final OidcTenantConfig tenantConfig;
    private final OidcTenantState state;
    private final Optional<OidcEndpointPolicy> endpointPolicy;
    private final OidcProviderMetadata metadata;
    private final OidcEndpointClient endpointClient;
    private final OidcJwkSetManager jwkSetManager;
    private final OidcCookieStateHandler cookieStateHandler;

    private OidcTenantContext(String tenantId,
                              OidcTenantConfig tenantConfig,
                              OidcTenantState state,
                              OidcProviderMetadata readyMetadata) {
        this.tenantId = tenantId;
        this.tenantConfig = tenantConfig;
        this.state = state;
        if (state == OidcTenantState.READY) {
            this.endpointPolicy = OidcConfigSupport.endpointPolicy(tenantConfig);
            this.metadata = readyMetadata;
            this.endpointClient = OidcEndpointClient.create(tenantConfig, metadata);
            this.jwkSetManager = OidcJwkSetManager.create(tenantId, metadata);
            this.cookieStateHandler = OidcCookieStateHandler.create(tenantConfig);
        } else {
            this.endpointPolicy = Optional.empty();
            this.metadata = null;
            this.endpointClient = null;
            this.jwkSetManager = null;
            this.cookieStateHandler = null;
        }
    }

    static OidcTenantContext ready(String tenantId, OidcTenantConfig tenantConfig) {
        return ready(tenantId, tenantConfig, OidcProviderMetadata.fromStaticConfig(tenantConfig));
    }

    static OidcTenantContext ready(String tenantId, OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        return new OidcTenantContext(tenantId, tenantConfig, OidcTenantState.READY, metadata);
    }

    static OidcTenantContext notReady(String tenantId, OidcTenantConfig tenantConfig) {
        return new OidcTenantContext(tenantId, tenantConfig, OidcTenantState.NOT_READY, null);
    }

    static OidcTenantContext disabled(String tenantId, OidcTenantConfig tenantConfig) {
        return new OidcTenantContext(tenantId, tenantConfig, OidcTenantState.DISABLED, null);
    }

    static OidcTenantContext failed(String tenantId, OidcTenantConfig tenantConfig) {
        return new OidcTenantContext(tenantId, tenantConfig, OidcTenantState.FAILED, null);
    }

    String tenantId() {
        return tenantId;
    }

    OidcTenantConfig tenantConfig() {
        return tenantConfig;
    }

    OidcTenantState state() {
        return state;
    }

    boolean ready() {
        return state == OidcTenantState.READY;
    }

    boolean cacheable() {
        return state != OidcTenantState.NOT_READY;
    }

    OidcProviderMetadata metadata() {
        requireReady();
        return metadata;
    }

    OidcEndpointClient endpointClient() {
        requireReady();
        return endpointClient;
    }

    OidcJwkSetManager jwkSetManager() {
        requireReady();
        return jwkSetManager;
    }

    OidcTokenValidationConfig tokenValidation() {
        requireReady();
        return tenantConfig.protectedResource()
                .map(OidcProtectedResourceConfig::tokenValidation)
                .orElseGet(OidcTokenValidationConfig::create);
    }

    OidcCookieStateHandler cookieStateHandler() {
        requireReady();
        return cookieStateHandler;
    }

    Optional<OidcEndpointPolicy> endpointPolicy() {
        if (!ready()) {
            return Optional.empty();
        }
        return endpointPolicy;
    }

    OidcTokenTransportConfig tokenTransport() {
        return tenantConfig.tokenTransport();
    }

    OidcSubjectMappingConfig subjectMapping() {
        return tenantConfig.subjectMapping();
    }

    private void requireReady() {
        if (!ready()) {
            throw new IllegalStateException("OIDC tenant runtime resources are available only when tenant is ready");
        }
    }
}
