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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import io.helidon.security.ProviderRequest;

final class OidcTenantRuntimeRegistry {
    private final OidcTenantResolver tenantResolver;
    private final OidcTenantConfigResolver tenantConfigResolver;
    private final ConcurrentMap<String, OidcTenantContext> contexts = new ConcurrentHashMap<>();

    private OidcTenantRuntimeRegistry(OidcTenantResolver tenantResolver,
                                      OidcTenantConfigResolver tenantConfigResolver) {
        this.tenantResolver = tenantResolver;
        this.tenantConfigResolver = tenantConfigResolver;
    }

    static OidcTenantRuntimeRegistry create(OidcProviderConfig config) {
        return new OidcTenantRuntimeRegistry(OidcTenantResolver.create(config),
                                             OidcTenantConfigResolver.create(config));
    }

    Optional<OidcTenantContext> tenantContext(ProviderRequest request) {
        return tenantResolver.tenantId(request)
                .flatMap(this::tenantContext);
    }

    Optional<OidcTenantContext> tenantContext(String tenantId) {
        Optional<OidcTenantConfig> tenantConfig = tenantConfigResolver.tenantConfig(tenantId);
        if (tenantConfig.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(contexts.computeIfAbsent(tenantId,
                                                    id -> OidcTenantContext.ready(id, tenantConfig.get())));
    }

    int cachedTenantCount() {
        return contexts.size();
    }
}
