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

import io.helidon.common.LazyValue;
import io.helidon.security.ProviderRequest;

final class OidcTenantRuntimeRegistry {
    private final OidcProviderConfig config;
    private final OidcTenantResolver tenantResolver;
    private final OidcTenantContextFactory tenantContextFactory;
    private final ConcurrentMap<String, LazyValue<OidcTenantContext>> contexts = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, OidcCookieStateHandler> cookieStateHandlers = new ConcurrentHashMap<>();

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
        return tenantConfig(tenantId)
                .map(tenantConfig -> {
                    OidcCookieStateHandler cookieStateHandler = cookieStateHandler(tenantId, tenantConfig);
                    /*
                     * The map callback installs only a lightweight lazy holder; it never performs discovery or other
                     * remote tenant initialization. LazyValue.get() runs after computeIfAbsent returns. Its first
                     * caller performs initialization synchronously, same-tenant callers wait without holding a map
                     * lock, and different tenant keys initialize independently.
                     *
                     * The default factory converts operational failures into a definitive FAILED context, which the
                     * LazyValue caches like READY and DISABLED contexts. If the factory violates its contract and
                     * throws instead, LazyValue remains unloaded so a later caller can retry.
                     */
                    LazyValue<OidcTenantContext> context = contexts.computeIfAbsent(
                            tenantId,
                            _ -> LazyValue.create(() -> tenantContextFactory.create(tenantId, tenantConfig)
                                    .withCookieStateHandler(cookieStateHandler)));
                    return context.get();
                });
    }

    Optional<OidcCookieStateHandler> cookieStateHandler(String tenantId) {
        return tenantConfig(tenantId).map(tenantConfig -> cookieStateHandler(tenantId, tenantConfig));
    }

    int cachedTenantCount() {
        return contexts.size();
    }

    private Optional<OidcTenantConfig> tenantConfig(String tenantId) {
        return Optional.ofNullable(config.tenants().get(tenantId));
    }

    private OidcCookieStateHandler cookieStateHandler(String tenantId, OidcTenantConfig tenantConfig) {
        /*
         * Handler construction is deliberately lightweight: PBKDF2 and HKDF remain behind the handler's LazyValue.
         * computeIfAbsent therefore does not run expensive cryptography under a ConcurrentHashMap bin lock. The same
         * retained handler serves callback routing, logout, and the initialized tenant context, so key derivation runs
         * at most once for a tenant registry and only when a cookie is first protected or read.
         */
        return cookieStateHandlers.computeIfAbsent(tenantId,
                                                   _ -> OidcCookieStateHandler.create(tenantId, tenantConfig));
    }
}
