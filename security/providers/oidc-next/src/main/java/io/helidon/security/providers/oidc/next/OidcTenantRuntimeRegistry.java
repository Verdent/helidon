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

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;

import io.helidon.security.ProviderRequest;

final class OidcTenantRuntimeRegistry {
    private final OidcProviderConfig config;
    private final OidcTenantResolver tenantResolver;
    private final OidcTenantContextFactory tenantContextFactory;
    private final Clock clock;
    private final ConcurrentMap<String, TenantContextSlot> contexts = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, OidcCookieStateHandler> cookieStateHandlers = new ConcurrentHashMap<>();

    private OidcTenantRuntimeRegistry(OidcProviderConfig config,
                                      OidcTenantResolver tenantResolver,
                                      OidcTenantContextFactory tenantContextFactory,
                                      Clock clock) {
        this.config = config;
        this.tenantResolver = tenantResolver;
        this.tenantContextFactory = tenantContextFactory;
        this.clock = clock;
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
                                             tenantContextFactory,
                                             Clock.systemUTC());
    }

    static OidcTenantRuntimeRegistry create(OidcProviderConfig config,
                                            OidcTenantContextFactory tenantContextFactory,
                                            Clock clock) {
        return new OidcTenantRuntimeRegistry(config,
                                             new OidcTenantResolver(config),
                                             tenantContextFactory,
                                             clock);
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
                     * The map callback installs only a lightweight per-tenant slot; remote initialization runs after
                     * computeIfAbsent returns. Same-tenant callers share one attempt, while different tenants initialize
                     * independently. Retryable discovery failures remain cached until the configured retry interval.
                     */
                    TenantContextSlot context = contexts.computeIfAbsent(
                            tenantId,
                            _ -> new TenantContextSlot(tenantId,
                                                       tenantConfig,
                                                       cookieStateHandler,
                                                       tenantContextFactory,
                                                       clock));
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

    private static final class TenantContextSlot {
        private final String tenantId;
        private final OidcTenantConfig tenantConfig;
        private final OidcCookieStateHandler cookieStateHandler;
        private final OidcTenantContextFactory tenantContextFactory;
        private final Clock clock;
        private final ReentrantLock initializationLock = new ReentrantLock();
        private volatile OidcTenantContext context;
        private volatile Instant retryAfter;

        private TenantContextSlot(String tenantId,
                                  OidcTenantConfig tenantConfig,
                                  OidcCookieStateHandler cookieStateHandler,
                                  OidcTenantContextFactory tenantContextFactory,
                                  Clock clock) {
            this.tenantId = tenantId;
            this.tenantConfig = tenantConfig;
            this.cookieStateHandler = cookieStateHandler;
            this.tenantContextFactory = tenantContextFactory;
            this.clock = clock;
        }

        private OidcTenantContext get() {
            OidcTenantContext current = context;
            if (current != null && reusable(current, clock.instant())) {
                return current;
            }
            initializationLock.lock();
            try {
                current = context;
                if (current != null && reusable(current, clock.instant())) {
                    return current;
                }
                OidcTenantContext initialized = tenantContextFactory.create(tenantId, tenantConfig)
                        .withCookieStateHandler(cookieStateHandler);
                retryAfter = initialized.retryableFailure()
                        ? clock.instant().plus(tenantConfig.initializationRetryInterval())
                        : null;
                context = initialized;
                return initialized;
            } finally {
                initializationLock.unlock();
            }
        }

        private boolean reusable(OidcTenantContext current, Instant now) {
            Instant retryTime = retryAfter;
            return !current.retryableFailure() || (retryTime != null && now.isBefore(retryTime));
        }
    }
}
