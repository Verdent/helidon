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
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import io.helidon.security.ProviderRequest;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;

final class OidcTenantRuntimeRegistry {
    private static final System.Logger LOGGER = System.getLogger(OidcTenantRuntimeRegistry.class.getName());

    private final OidcProviderConfig config;
    private final OidcTenantResolver tenantResolver;
    private final OidcTenantContextFactory tenantContextFactory;
    private final Clock clock;
    private final ConcurrentMap<String, TenantContextSlot> contexts = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, OidcCookieStateHandler> cookieStateHandlers = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, OidcBackChannelLogoutStore> logoutStores = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, OidcRemoteWorkLimiter> logoutWorkLimiters = new ConcurrentHashMap<>();
    private final ReentrantLock lifecycleLock = new ReentrantLock();

    private volatile boolean closed;
    private int featureReferences;

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
                      OidcTenantContextFactory.create(OidcMixUpProtection.issuerParameterRequiredTenants(config)));
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
        return select(request).flatMap(selection -> tenantContext(selection.tenantId()));
    }

    Optional<OidcTenantConfig> tenantConfig(ProviderRequest request) {
        return select(request).map(TenantSelection::config);
    }

    Optional<TenantSelection> select(ProviderRequest request) {
        requireOpen();
        return tenantResolver.tenantId(request)
                .flatMap(tenantId -> tenantConfig(tenantId)
                        .map(tenantConfig -> new TenantSelection(tenantId, tenantConfig)));
    }

    Optional<OidcTenantContext> tenantContext(String tenantId) {
        requireOpen();
        TenantContextSlot cached = contexts.get(tenantId);
        if (cached != null) {
            return Optional.of(cached.get());
        }
        Optional<TenantContextSlot> slot;
        lifecycleLock.lock();
        try {
            slot = tenantConfig(tenantId).map(tenantConfig -> contexts.computeIfAbsent(tenantId,
                    _ -> new TenantContextSlot(tenantId, tenantConfig, cookieStateHandler(tenantId, tenantConfig))));
        } finally {
            lifecycleLock.unlock();
        }
        // Only slot installation is guarded by the lifecycle lock; initialization and remote I/O run outside it.
        return slot.map(TenantContextSlot::get);
    }

    Optional<OidcCookieStateHandler> cookieStateHandler(String tenantId) {
        requireOpen();
        OidcCookieStateHandler cached = cookieStateHandlers.get(tenantId);
        if (cached != null) {
            return Optional.of(cached);
        }
        lifecycleLock.lock();
        try {
            return tenantConfig(tenantId).map(tenantConfig -> cookieStateHandler(tenantId, tenantConfig));
        } finally {
            lifecycleLock.unlock();
        }
    }

    Optional<OidcBackChannelLogoutStore> logoutStore(String tenantId) {
        requireOpen();
        return tenantConfig(tenantId)
                .filter(OidcTenantConfig::enabled)
                .flatMap(OidcTenantConfig::logout)
                .filter(OidcLogoutConfig::enabled)
                .flatMap(OidcLogoutConfig::backChannel)
                .map(config -> logoutStores.computeIfAbsent(tenantId,
                                                             _ -> config.store().orElseGet(OidcInMemoryLogoutStore::new)));
    }

    Optional<OidcRemoteWorkLimiter> logoutWorkLimiter(String tenantId) {
        requireOpen();
        return tenantConfig(tenantId)
                .filter(OidcTenantConfig::enabled)
                .flatMap(OidcTenantConfig::logout)
                .filter(OidcLogoutConfig::enabled)
                .flatMap(OidcLogoutConfig::backChannel)
                .map(config -> logoutWorkLimiters.computeIfAbsent(tenantId,
                                                                   _ -> new OidcRemoteWorkLimiter(config.remoteWork())));
    }

    int cachedTenantCount() {
        return contexts.size();
    }

    void requireOpen() {
        if (closed) {
            throw new IllegalStateException("OIDC tenant runtime is closed");
        }
    }

    void retainFeature() {
        lifecycleLock.lock();
        try {
            requireOpen();
            featureReferences++;
        } finally {
            lifecycleLock.unlock();
        }
    }

    void releaseFeature() {
        List<TenantContextSlot> toClose;
        lifecycleLock.lock();
        try {
            if (featureReferences == 0) {
                throw new IllegalStateException("OIDC feature runtime was not retained");
            }
            if (--featureReferences != 0) {
                return;
            }
            toClose = closeLocked();
        } finally {
            lifecycleLock.unlock();
        }
        closeSlots(toClose);
    }

    void close() {
        List<TenantContextSlot> toClose;
        lifecycleLock.lock();
        try {
            toClose = closeLocked();
        } finally {
            lifecycleLock.unlock();
        }
        closeSlots(toClose);
    }

    private static void closeSlots(List<TenantContextSlot> slots) {
        Throwable failure = null;
        for (TenantContextSlot slot : slots) {
            try {
                slot.close();
            } catch (RuntimeException | Error e) {
                if (failure == null) {
                    failure = e;
                } else if (failure != e) {
                    failure.addSuppressed(e);
                }
            }
        }
        if (failure instanceof RuntimeException runtimeException) {
            throw runtimeException;
        }
        if (failure instanceof Error error) {
            throw error;
        }
    }

    private List<TenantContextSlot> closeLocked() {
        if (closed) {
            return List.of();
        }
        closed = true;
        List<TenantContextSlot> result = List.copyOf(contexts.values());
        contexts.clear();
        cookieStateHandlers.clear();
        logoutStores.clear();
        logoutWorkLimiters.clear();
        return result;
    }

    private Optional<OidcTenantConfig> tenantConfig(String tenantId) {
        requireOpen();
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

    record TenantSelection(String tenantId, OidcTenantConfig config) {
    }

    static final class UnavailableException extends IllegalStateException {
        private UnavailableException() {
            super(Thread.currentThread().isInterrupted()
                          ? "Interrupted while waiting for OIDC tenant initialization"
                          : "OIDC tenant initialization capacity is exhausted");
        }
    }

    private final class TenantContextSlot {
        private final String tenantId;
        private final OidcTenantConfig tenantConfig;
        private final OidcCookieStateHandler cookieStateHandler;
        private final OidcRemoteWorkLimiter initializationAdmission;
        private final AtomicReference<OidcTenantContext> context = new AtomicReference<>();
        private volatile Instant retryAfter;

        private TenantContextSlot(String tenantId,
                                  OidcTenantConfig tenantConfig,
                                  OidcCookieStateHandler cookieStateHandler) {
            this.tenantId = tenantId;
            this.tenantConfig = tenantConfig;
            this.cookieStateHandler = cookieStateHandler;
            this.initializationAdmission = new OidcRemoteWorkLimiter(OidcRemoteWorkConfig.builder()
                                                                            .maxConcurrent(1)
                                                                            .maxQueued(tenantConfig.initializationMaxQueued())
                                                                            .buildPrototype());
        }

        private OidcTenantContext get() {
            requireOpen();
            OidcTenantContext current = context.get();
            if (current != null && reusable(current, clock.instant())) {
                return current;
            }
            Optional<OidcRemoteWorkLimiter.Permit> permit = initializationAdmission.acquireActiveWithoutTimeout();
            if (permit.isEmpty()) {
                requireOpen();
                UnavailableException failure = new UnavailableException();
                if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                    LOGGER.log(System.Logger.Level.DEBUG,
                               "OIDC tenant initialization admission failed: tenant="
                                       + OidcDiagnostics.sanitizeLogValue(tenantId) + ", reason=" + failure.getMessage());
                }
                // This caller's rejection is not an initialization failure and must not be published or cached.
                throw failure;
            }
            try (OidcRemoteWorkLimiter.Permit _ = permit.orElseThrow()) {
                requireOpen();
                current = context.get();
                if (current != null && reusable(current, clock.instant())) {
                    return current;
                }
                OidcTenantContext initialized = tenantContextFactory.create(tenantId, tenantConfig)
                        .withCookieStateHandler(cookieStateHandler);
                retryAfter = initialized.retryableFailure()
                        ? clock.instant().plus(tenantConfig.initializationRetryInterval())
                        : null;
                context.set(initialized);
                if (closed) {
                    // Close claims the published context atomically, including initialization finishing after shutdown.
                    close();
                    requireOpen();
                }
                return initialized;
            }
        }

        private void close() {
            OidcTenantContext current = context.getAndSet(null);
            if (current != null && current.ready()) {
                current.webClient().closeResource();
            }
        }

        private boolean reusable(OidcTenantContext current, Instant now) {
            Instant retryTime = retryAfter;
            return !current.retryableFailure() || (retryTime != null && now.isBefore(retryTime));
        }
    }
}
