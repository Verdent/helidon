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

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.WebClient;

final class OidcJwkSetManager {
    private final String tenantId;
    private final OidcProviderMetadata metadata;
    private final OidcJwkSetConfig config;
    private final OidcJwkSetLoader jwkSetLoader;
    private final Clock clock;
    private final ReentrantLock refreshLock = new ReentrantLock();
    private volatile JwkKeys cachedJwkKeys;
    private volatile Instant lastJwkSetLoad;
    private volatile Instant lastJwkSetRefreshAttempt;
    private volatile RuntimeException lastJwkSetRefreshFailure;
    private Instant lastUnknownKeyIdRefreshAttempt;

    private OidcJwkSetManager(String tenantId,
                              OidcProviderMetadata metadata,
                              OidcJwkSetConfig config,
                              OidcJwkSetLoader jwkSetLoader,
                              Clock clock) {
        this.tenantId = tenantId;
        this.metadata = metadata;
        this.config = config;
        this.jwkSetLoader = jwkSetLoader;
        this.clock = clock;
    }

    static OidcJwkSetManager create(String tenantId,
                                    OidcProviderMetadata metadata,
                                    WebClient webClient,
                                    OidcJwkSetConfig config) {
        return new OidcJwkSetManager(tenantId, metadata, config, new OidcJwkSetLoader(webClient), Clock.systemUTC());
    }

    static OidcJwkSetManager create(String tenantId,
                                    OidcProviderMetadata metadata,
                                    Clock clock,
                                    OidcJwkSetConfig config) {
        return new OidcJwkSetManager(tenantId, metadata, config, new OidcJwkSetLoader(WebClient.create()), clock);
    }

    Optional<URI> jwkSetUri() {
        return metadata.jwkSetUri();
    }

    JwkKeys jwkKeys() {
        JwkKeys current = cachedJwkKeys;
        if (current != null) {
            if (refreshIntervalElapsed()) {
                return refreshExpiredJwkKeys(current);
            }
            RuntimeException refreshFailure = lastJwkSetRefreshFailure;
            if (refreshFailure != null) {
                throw refreshFailure;
            }
            return current;
        }

        return initialJwkKeys();
    }

    JwkKeys jwkKeys(Optional<String> keyId) {
        JwkKeys current = jwkKeys();
        JwkKeys availableKeys = current;
        Optional<String> unknownKeyId = keyId.filter(kid -> availableKeys.forKeyId(kid).isEmpty());
        if (unknownKeyId.isEmpty()) {
            return current;
        }
        return refreshUnknownKeyId(unknownKeyId.orElseThrow(), current);
    }

    private JwkKeys loadJwkKeys() {
        URI uri = jwkSetUri()
                .orElseThrow(() -> new IllegalStateException("JWK Set URI is not configured for tenant: "
                                                                     + OidcDiagnostics.sanitizeLogValue(tenantId)));
        try {
            return jwkSetLoader.load(uri, metadata.jwkSetUriFromWellKnownMetadata());
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to load JWK Set for tenant: "
                                                    + OidcDiagnostics.sanitizeLogValue(tenantId)
                                                    + ", uri=" + OidcDiagnostics.safeUri(uri),
                                            e);
        }
    }

    private JwkKeys initialJwkKeys() {
        refreshLock.lock();
        try {
            JwkKeys current = cachedJwkKeys;
            if (current != null) {
                return current;
            }
            return refreshJwkKeys();
        } finally {
            refreshLock.unlock();
        }
    }

    private JwkKeys refreshExpiredJwkKeys(JwkKeys staleKeys) {
        if (config.staleOnError()) {
            if (!refreshLock.tryLock()) {
                return staleKeys;
            }
        } else {
            refreshLock.lock();
        }

        try {
            JwkKeys current = cachedJwkKeys;
            if (current == null) {
                return refreshJwkKeys();
            }
            if (!refreshIntervalElapsed()) {
                return current;
            }
            try {
                return refreshJwkKeys();
            } catch (RuntimeException e) {
                lastJwkSetRefreshAttempt = clock.instant();
                if (config.staleOnError()) {
                    return current;
                }
                lastJwkSetRefreshFailure = e;
                throw e;
            }
        } finally {
            refreshLock.unlock();
        }
    }

    private JwkKeys refreshUnknownKeyId(String keyId, JwkKeys staleKeys) {
        if (!config.unknownKeyIdRefreshEnabled()) {
            return staleKeys;
        }
        refreshLock.lock();
        try {
            JwkKeys current = cachedJwkKeys;
            if (current == null) {
                current = refreshJwkKeys();
            }
            if (current.forKeyId(keyId).isPresent()) {
                return current;
            }
            if (!unknownKeyIdRefreshAllowed()) {
                return current;
            }
            try {
                JwkKeys loaded = loadJwkKeys();
                cacheJwkKeys(loaded);
                return loaded;
            } catch (RuntimeException e) {
                if (config.staleOnError()) {
                    return current;
                }
                throw e;
            }
        } finally {
            refreshLock.unlock();
        }
    }

    private JwkKeys refreshJwkKeys() {
        JwkKeys loaded = loadJwkKeys();
        cacheJwkKeys(loaded);
        return loaded;
    }

    private void cacheJwkKeys(JwkKeys loaded) {
        cachedJwkKeys = loaded;
        Instant now = clock.instant();
        lastJwkSetLoad = now;
        lastJwkSetRefreshAttempt = now;
        lastJwkSetRefreshFailure = null;
    }

    private boolean unknownKeyIdRefreshAllowed() {
        Instant lastLoad = lastJwkSetLoad;
        Instant now = clock.instant();
        Duration refreshInterval = config.unknownKeyIdRefreshInterval();
        if (lastLoad == null || now.isBefore(lastLoad.plus(refreshInterval))) {
            return false;
        }
        Instant lastAttempt = lastUnknownKeyIdRefreshAttempt;
        if (lastAttempt != null && now.isBefore(lastAttempt.plus(refreshInterval))) {
            return false;
        }
        lastUnknownKeyIdRefreshAttempt = now;
        return true;
    }

    private boolean refreshIntervalElapsed() {
        Instant lastRefresh = lastJwkSetRefreshAttempt;
        if (lastRefresh == null) {
            return false;
        }
        return config.refreshInterval()
                .map(interval -> !clock.instant().isBefore(lastRefresh.plus(interval)))
                .orElse(false);
    }
}
