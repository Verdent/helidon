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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import io.helidon.security.ProviderRequest;

final class OidcTenantRuntimeRegistry {
    private final OidcProviderConfig config;
    private final OidcTenantResolver tenantResolver;
    private final OidcTenantContextFactory tenantContextFactory;
    private final ConcurrentMap<String, CompletableFuture<OidcTenantContext>> contexts = new ConcurrentHashMap<>();

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
                              OidcOutboundPolicy.targetClientCredentialsGrantEnabled(config.outboundTargets()),
                              OidcOutboundPolicy.targetTokenExchangeEnabled(config.outboundTargets())));
    }

    static OidcTenantRuntimeRegistry create(OidcProviderConfig config,
                                            OidcTenantContextFactory tenantContextFactory) {
        return new OidcTenantRuntimeRegistry(config,
                                             new OidcTenantResolver(config),
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
        CompletableFuture<OidcTenantContext> existing = contexts.get(tenantId);
        if (existing != null) {
            return Optional.of(existing.join());
        }

        return tenantConfig(tenantId)
                .map(tenantConfig -> initialize(tenantId, tenantConfig));
    }

    int cachedTenantCount() {
        return contexts.size();
    }

    private Optional<OidcTenantConfig> tenantConfig(String tenantId) {
        return Optional.ofNullable(config.tenants().get(tenantId));
    }

    private OidcTenantContext initialize(String tenantId, OidcTenantConfig tenantConfig) {
        /*
         * Tenant creation may perform discovery and other remote I/O. Keep it outside ConcurrentMap update callbacks:
         * a slow callback holds map-internal update coordination and can block a different tenant whose key happens to
         * occupy the same bin. The future map performs only atomic leader election here. Callers for the same tenant
         * join the elected leader without holding a map lock, while different tenants initialize independently.
         *
         * Initialization is deliberately synchronous: the elected caller performs the work and returns only after the
         * tenant has reached a definitive READY, DISABLED, or FAILED state. The incomplete future is merely a wait point
         * for concurrent callers. Once completed, the same map entry becomes the permanent context cache.
         */
        CompletableFuture<OidcTenantContext> loading = new CompletableFuture<>();
        CompletableFuture<OidcTenantContext> existing = contexts.putIfAbsent(tenantId, loading);
        if (existing != null) {
            return existing.join();
        }

        try {
            OidcTenantContext created = tenantContextFactory.create(tenantId, tenantConfig);
            loading.complete(created);
            return created;
        } catch (RuntimeException | Error e) {
            loading.completeExceptionally(e);
            // Factory contract violations are not tenant outcomes and must not poison all later requests permanently.
            contexts.remove(tenantId, loading);
            throw e;
        }
    }
}
