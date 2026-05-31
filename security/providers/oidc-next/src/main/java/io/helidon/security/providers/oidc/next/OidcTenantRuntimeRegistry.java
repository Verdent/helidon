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
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.security.ProviderRequest;

final class OidcTenantRuntimeRegistry {
    private final OidcProviderConfig config;
    private final OidcTenantResolver tenantResolver;
    private final OidcTenantContextFactory tenantContextFactory;
    private final ConcurrentMap<String, OidcTenantContext> contexts = new ConcurrentHashMap<>();

    private OidcTenantRuntimeRegistry(OidcProviderConfig config,
                                      OidcTenantResolver tenantResolver,
                                      OidcTenantContextFactory tenantContextFactory) {
        this.config = config;
        this.tenantResolver = tenantResolver;
        this.tenantContextFactory = tenantContextFactory;
    }

    static OidcTenantRuntimeRegistry create(OidcProviderConfig config) {
        return create(config,
                      OidcTenantContextFactory.create(
                              OidcConfigSupport.targetClientCredentialsGrantEnabled(config.outboundTargets())));
    }

    static OidcTenantRuntimeRegistry create(OidcProviderConfig config,
                                            OidcTenantContextFactory tenantContextFactory) {
        return new OidcTenantRuntimeRegistry(config,
                                             OidcTenantResolver.create(config),
                                             tenantContextFactory);
    }

    Optional<OidcTenantContext> tenantContext(ProviderRequest request) {
        return tenantResolver.tenantId(request)
                .flatMap(this::tenantContext);
    }

    Optional<OidcTenantConfig> tenantConfig(ProviderRequest request) {
        return tenantResolver.tenantId(request)
                .flatMap(this::tenantConfig);
    }

    Optional<OidcTenantContext> tenantContext(String tenantId) {
        OidcTenantContext existing = contexts.get(tenantId);
        if (existing != null) {
            return Optional.of(existing);
        }

        return tenantConfig(tenantId)
                .map(tenantConfig -> {
                    AtomicReference<OidcTenantContext> resolvedContext = new AtomicReference<>();
                    contexts.compute(tenantId, (id, cached) -> {
                        if (cached != null) {
                            resolvedContext.set(cached);
                            return cached;
                        }

                        OidcTenantContext created = tenantContextFactory.create(id, tenantConfig);
                        resolvedContext.set(created);
                        return created.cacheable() ? created : null;
                    });
                    return resolvedContext.get();
                });
    }

    int cachedTenantCount() {
        return contexts.size();
    }

    private Optional<OidcTenantConfig> tenantConfig(String tenantId) {
        return Optional.ofNullable(config.tenants().get(tenantId));
    }
}
