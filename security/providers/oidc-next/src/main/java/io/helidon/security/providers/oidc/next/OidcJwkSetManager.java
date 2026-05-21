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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import io.helidon.security.jwt.jwk.JwkKeys;

final class OidcJwkSetManager {
    private static final int UNKNOWN_KEY_ID_REFRESH_ATTEMPT_LIMIT = 64;

    static final Duration UNKNOWN_KEY_ID_REFRESH_INTERVAL = Duration.ofMinutes(5);

    private final String tenantId;
    private final OidcProviderMetadata metadata;
    private final OidcJwkSetLoader jwkSetLoader;
    private final Clock clock;
    private volatile JwkKeys cachedJwkKeys;
    private volatile Instant lastJwkSetLoad;
    private boolean unknownKeyIdRefreshInProgress;
    private final Map<String, Instant> unknownKeyIdRefreshAttempts =
            new LinkedHashMap<>() {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Instant> eldest) {
                    return size() > UNKNOWN_KEY_ID_REFRESH_ATTEMPT_LIMIT;
                }
            };

    private OidcJwkSetManager(String tenantId,
                              OidcProviderMetadata metadata,
                              OidcJwkSetLoader jwkSetLoader,
                              Clock clock) {
        this.tenantId = tenantId;
        this.metadata = metadata;
        this.jwkSetLoader = jwkSetLoader;
        this.clock = clock;
    }

    static OidcJwkSetManager create(String tenantId, OidcProviderMetadata metadata) {
        return create(tenantId, metadata, Clock.systemUTC());
    }

    static OidcJwkSetManager create(String tenantId, OidcProviderMetadata metadata, Clock clock) {
        return new OidcJwkSetManager(tenantId, metadata, OidcJwkSetLoader.create(), clock);
    }

    String tenantId() {
        return tenantId;
    }

    Optional<URI> jwkSetUri() {
        return metadata.jwkSetUri();
    }

    JwkKeys jwkKeys() {
        JwkKeys current = cachedJwkKeys;
        if (current != null) {
            return current;
        }

        return refreshJwkKeys();
    }

    JwkKeys jwkKeys(Optional<String> keyId) {
        JwkKeys current = jwkKeys();
        JwkKeys availableKeys = current;
        Optional<String> unknownKeyId = keyId.filter(kid -> availableKeys.forKeyId(kid).isEmpty());
        if (unknownKeyId.isEmpty()) {
            return current;
        }
        String unknownKey = unknownKeyId.orElseThrow();
        if (!beginUnknownKeyIdRefresh(unknownKey)) {
            return current;
        }
        try {
            return refreshJwkKeys(unknownKey);
        } finally {
            completeUnknownKeyIdRefresh();
        }
    }

    private JwkKeys loadJwkKeys() {
        URI uri = jwkSetUri()
                .orElseThrow(() -> new IllegalStateException("JWK Set URI is not configured for tenant: " + tenantId));
        try {
            return jwkSetLoader.load(uri);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to load JWK Set for tenant: " + tenantId, e);
        }
    }

    private JwkKeys refreshJwkKeys() {
        JwkKeys loaded = loadJwkKeys();
        cacheJwkKeys(loaded, true);
        return loaded;
    }

    private JwkKeys refreshJwkKeys(String expectedKeyId) {
        JwkKeys loaded = loadJwkKeys();
        cacheJwkKeys(loaded, loaded.forKeyId(expectedKeyId).isPresent());
        return loaded;
    }

    private synchronized void cacheJwkKeys(JwkKeys loaded, boolean updateLoadTime) {
        cachedJwkKeys = loaded;
        if (updateLoadTime) {
            lastJwkSetLoad = clock.instant();
        }
    }

    private synchronized boolean beginUnknownKeyIdRefresh(String keyId) {
        if (unknownKeyIdRefreshInProgress) {
            return false;
        }
        Instant lastLoad = lastJwkSetLoad;
        Instant now = clock.instant();
        if (lastLoad == null || now.isBefore(lastLoad.plus(UNKNOWN_KEY_ID_REFRESH_INTERVAL))) {
            return false;
        }
        Instant lastAttempt = unknownKeyIdRefreshAttempts.get(keyId);
        if (lastAttempt != null && now.isBefore(lastAttempt.plus(UNKNOWN_KEY_ID_REFRESH_INTERVAL))) {
            return false;
        }
        unknownKeyIdRefreshAttempts.put(keyId, now);
        unknownKeyIdRefreshInProgress = true;
        return true;
    }

    private synchronized void completeUnknownKeyIdRefresh() {
        unknownKeyIdRefreshInProgress = false;
    }
}
