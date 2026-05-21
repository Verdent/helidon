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
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import io.helidon.security.jwt.jwk.JwkKeys;

final class OidcJwkSetManager {
    private static final Duration UNKNOWN_KEY_ID_REFRESH_INTERVAL = Duration.ofMinutes(5);

    private final String tenantId;
    private final OidcProviderMetadata metadata;
    private final OidcJwkSetLoader jwkSetLoader;
    private volatile JwkKeys cachedJwkKeys;
    private Instant lastUnknownKeyIdRefreshAttempt;

    private OidcJwkSetManager(String tenantId, OidcProviderMetadata metadata, OidcJwkSetLoader jwkSetLoader) {
        this.tenantId = tenantId;
        this.metadata = metadata;
        this.jwkSetLoader = jwkSetLoader;
    }

    static OidcJwkSetManager create(String tenantId, OidcProviderMetadata metadata) {
        return new OidcJwkSetManager(tenantId, metadata, OidcJwkSetLoader.create());
    }

    String tenantId() {
        return tenantId;
    }

    Optional<URI> jwkSetUri() {
        return metadata.jwkSetUri();
    }

    synchronized JwkKeys jwkKeys() {
        JwkKeys current = cachedJwkKeys;
        if (current != null) {
            return current;
        }

        return refreshJwkKeys();
    }

    synchronized JwkKeys jwkKeys(Optional<String> keyId) {
        JwkKeys current = cachedJwkKeys;
        if (current == null) {
            current = refreshJwkKeys();
        }
        JwkKeys availableKeys = current;
        Optional<String> unknownKeyId = keyId.filter(kid -> availableKeys.forKeyId(kid).isEmpty());
        if (unknownKeyId.isEmpty() || !unknownKeyIdRefreshAllowed(Instant.now())) {
            return current;
        }
        return refreshJwkKeys();
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
        cachedJwkKeys = loaded;
        return loaded;
    }

    private boolean unknownKeyIdRefreshAllowed(Instant now) {
        if (lastUnknownKeyIdRefreshAttempt == null
                || !now.isBefore(lastUnknownKeyIdRefreshAttempt.plus(UNKNOWN_KEY_ID_REFRESH_INTERVAL))) {
            lastUnknownKeyIdRefreshAttempt = now;
            return true;
        }
        return false;
    }
}
