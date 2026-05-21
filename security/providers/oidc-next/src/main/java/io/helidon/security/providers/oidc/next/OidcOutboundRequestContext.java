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

import io.helidon.security.EndpointConfig;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;

final class OidcOutboundRequestContext {
    private final ProviderRequest providerRequest;
    private final SecurityEnvironment outboundEnvironment;
    private final EndpointConfig outboundConfig;
    private final Optional<OidcTenantContext> tenantContext;

    private OidcOutboundRequestContext(ProviderRequest providerRequest,
                                       SecurityEnvironment outboundEnvironment,
                                       EndpointConfig outboundConfig,
                                       OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this.providerRequest = providerRequest;
        this.outboundEnvironment = outboundEnvironment;
        this.outboundConfig = outboundConfig;
        this.tenantContext = tenantRuntimeRegistry.tenantContext(providerRequest);
    }

    static OidcOutboundRequestContext create(ProviderRequest providerRequest,
                                             SecurityEnvironment outboundEnvironment,
                                             EndpointConfig outboundConfig,
                                             OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcOutboundRequestContext(providerRequest,
                                              outboundEnvironment,
                                              outboundConfig,
                                              tenantRuntimeRegistry);
    }

    Optional<OidcOutboundPolicy> outboundPolicy() {
        if (tenantContext.isEmpty()) {
            return Optional.empty();
        }

        if (outboundConfig == null) {
            return tenantContext.flatMap(OidcTenantContext::outboundPolicy);
        }
        return outboundConfig.instance(OidcOutboundPolicy.class)
                .or(() -> tenantContext.flatMap(OidcTenantContext::outboundPolicy));
    }

    ProviderRequest providerRequest() {
        return providerRequest;
    }

    SecurityEnvironment outboundEnvironment() {
        return outboundEnvironment;
    }
}
