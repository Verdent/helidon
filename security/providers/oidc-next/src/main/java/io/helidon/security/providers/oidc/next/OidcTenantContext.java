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
    private final Optional<OidcOutboundPolicy> outboundPolicy;

    private OidcTenantContext(String tenantId, OidcTenantConfig tenantConfig, OidcTenantState state) {
        this.tenantId = tenantId;
        this.tenantConfig = tenantConfig;
        this.state = state;
        this.endpointPolicy = OidcConfigSupport.endpointPolicy(tenantConfig);
        this.outboundPolicy = OidcConfigSupport.outboundPolicy(tenantConfig);
    }

    static OidcTenantContext ready(String tenantId, OidcTenantConfig tenantConfig) {
        return new OidcTenantContext(tenantId, tenantConfig, OidcTenantState.READY);
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

    Optional<OidcEndpointPolicy> endpointPolicy() {
        return endpointPolicy;
    }

    Optional<OidcOutboundPolicy> outboundPolicy() {
        return outboundPolicy;
    }

    OidcTokenTransportConfig tokenTransport() {
        return tenantConfig.tokenTransport();
    }
}
