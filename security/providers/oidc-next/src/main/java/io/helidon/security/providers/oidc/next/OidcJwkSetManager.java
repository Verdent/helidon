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
import java.util.function.Function;
import java.util.function.Supplier;

import io.helidon.common.configurable.ResourceConfig;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.WebClient;

final class OidcJwkSetManager {
    private final String tenantId;
    private final Optional<URI> jwkSetUri;
    private final OidcJwkSetConfig config;
    private final Supplier<JwkKeys> keyLoader;
    private final Clock clock;
    private final OidcRemoteWorkLimiter refreshAdmission;
    private volatile JwkSetState state = JwkSetState.empty();
    private Instant lastUnknownKeyIdRefreshAttempt;

    private OidcJwkSetManager(String tenantId,
                              Optional<URI> jwkSetUri,
                              OidcJwkSetConfig config,
                              Supplier<JwkKeys> keyLoader,
                              Clock clock) {
        this.tenantId = tenantId;
        this.jwkSetUri = jwkSetUri;
        this.config = config;
        this.keyLoader = keyLoader;
        this.clock = clock;
        this.refreshAdmission = new OidcRemoteWorkLimiter(OidcRemoteWorkConfig.builder()
                                                                .maxConcurrent(1)
                                                                .maxQueued(config.maxQueued())
                                                                .admissionTimeout(config.admissionTimeout())
                                                                .buildPrototype());
    }

    static OidcJwkSetManager create(String tenantId,
                                    OidcProviderMetadata metadata,
                                    WebClient webClient,
                                    OidcJwkSetConfig config) {
        return create(tenantId, metadata, webClient, Clock.systemUTC(), config);
    }

    static OidcJwkSetManager create(String tenantId,
                                    OidcProviderMetadata metadata,
                                    Clock clock,
                                    OidcJwkSetConfig config) {
        return create(tenantId, metadata, WebClient.create(), clock, config);
    }

    static OidcJwkSetManager create(String tenantId,
                                    OidcProviderMetadata metadata,
                                    WebClient webClient,
                                    Clock clock,
                                    OidcJwkSetConfig config) {
        return create(tenantId, metadata, webClient, clock, config, _ -> Optional.empty());
    }

    static OidcJwkSetManager create(String tenantId,
                                    OidcProviderMetadata metadata,
                                    WebClient webClient,
                                    Clock clock,
                                    OidcJwkSetConfig config,
                                    Function<URI, Optional<String>> unauthorizedJwkSetAccessToken) {
        OidcJwkSetLoader loader = new OidcJwkSetLoader(webClient, unauthorizedJwkSetAccessToken);
        Optional<URI> uri = metadata.jwkSetUri();
        return new OidcJwkSetManager(tenantId, uri, config,
                                    () -> loader.load(uri.orElseThrow(() -> new IllegalStateException(
                                            "JWK Set URI is not configured for tenant: "
                                                    + OidcDiagnostics.sanitizeLogValue(tenantId)))), clock);
    }

    static OidcJwkSetManager createLocal(String tenantId,
                                         ResourceConfig verificationJwk,
                                         Clock clock,
                                         OidcJwkSetConfig config) {
        return new OidcJwkSetManager(tenantId, Optional.empty(), config,
                                    () -> OidcJwkSetLoader.loadLocal(verificationJwk), clock);
    }

    Optional<URI> jwkSetUri() {
        return jwkSetUri;
    }

    JwkKeys jwkKeys() {
        JwkSetState current = state;
        if (current.keys() != null) {
            if (refreshRequired(current)) {
                return refreshExpiredJwkKeys(current);
            }
            return currentAfterRefreshFailure(current);
        }

        if (current.refreshFailure() != null && !failureRetryIntervalElapsed(current)) {
            throw current.refreshFailure();
        }
        return initialJwkKeys(current);
    }

    JwkKeys jwkKeys(Optional<String> keyId) {
        JwkKeys current = jwkKeys();
        JwkKeys availableKeys = current;
        Optional<String> unknownKeyId = keyId.filter(kid -> availableKeys.forKeyId(kid).isEmpty());
        if (unknownKeyId.isEmpty()) {
            return current;
        }
        return refreshUnknownKeyId(unknownKeyId.orElseThrow(), current, state);
    }

    private JwkKeys loadJwkKeys() {
        try {
            return keyLoader.get();
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to load JWK Set for tenant: "
                                                    + OidcDiagnostics.sanitizeLogValue(tenantId)
                                                    + jwkSetUri.map(uri -> ", uri=" + OidcDiagnostics.safeUri(uri)).orElse(""),
                                            e);
        }
    }

    private JwkKeys initialJwkKeys(JwkSetState observed) {
        try (OidcRemoteWorkLimiter.Permit _ = acquireRefresh()) {
            JwkSetState current = state;
            if (current != observed) {
                return publishedOutcome(current);
            }
            return loadInitialJwkKeys(current);
        }
    }

    private JwkKeys refreshExpiredJwkKeys(JwkSetState observed) {
        try (OidcRemoteWorkLimiter.Permit _ = acquireRefresh()) {
            JwkSetState current = state;
            if (current != observed) {
                return publishedOutcome(current);
            }
            if (current.keys() == null) {
                return loadInitialJwkKeys(current);
            }
            if (!refreshRequired(current)) {
                return currentAfterRefreshFailure(current);
            }
            return refreshJwkKeys(current.keys());
        }
    }

    private JwkKeys refreshUnknownKeyId(String keyId, JwkKeys staleKeys, JwkSetState observed) {
        if (!config.unknownKeyIdRefreshEnabled()) {
            return staleKeys;
        }
        try (OidcRemoteWorkLimiter.Permit _ = acquireRefresh()) {
            JwkSetState currentState = state;
            if (currentState != observed) {
                return publishedOutcome(currentState);
            }
            JwkKeys current = currentState.keys();
            if (current == null) {
                current = loadInitialJwkKeys(currentState);
                currentState = state;
            }
            if (current.forKeyId(keyId).isPresent()) {
                return current;
            }
            if (currentState.refreshFailure() != null && !failureRetryIntervalElapsed(currentState)) {
                return currentAfterRefreshFailure(currentState);
            }
            if (!unknownKeyIdRefreshAllowed()) {
                return current;
            }
            try {
                JwkKeys loaded = loadJwkKeys();
                cacheJwkKeys(loaded);
                return loaded;
            } catch (RuntimeException e) {
                recordRefreshFailure(e);
                return staleOrThrow(current, e);
            }
        }
    }

    private OidcRemoteWorkLimiter.Permit acquireRefresh() {
        // One active permit replaces the refresh lock; rejection must not publish a load failure or permit stale keys.
        return refreshAdmission.acquireActive().orElseThrow(UnavailableException::new);
    }

    private JwkKeys loadInitialJwkKeys(JwkSetState current) {
        // Called only by the admitted coordinator; never reacquire its non-reentrant permit.
        if (current.keys() != null) {
            return refreshRequired(current) ? refreshJwkKeys(current.keys()) : currentAfterRefreshFailure(current);
        }
        if (current.refreshFailure() != null && !failureRetryIntervalElapsed(current)) {
            throw current.refreshFailure();
        }
        try {
            return refreshJwkKeys();
        } catch (RuntimeException e) {
            recordRefreshFailure(e);
            throw e;
        }
    }

    private JwkKeys refreshJwkKeys() {
        JwkKeys loaded = loadJwkKeys();
        cacheJwkKeys(loaded);
        return loaded;
    }

    private JwkKeys refreshJwkKeys(JwkKeys staleKeys) {
        try {
            return refreshJwkKeys();
        } catch (RuntimeException e) {
            recordRefreshFailure(e);
            return staleOrThrow(staleKeys, e);
        }
    }

    private JwkKeys staleOrThrow(JwkKeys staleKeys, RuntimeException refreshFailure) {
        if (config.staleOnError()) {
            return staleKeys;
        }
        throw refreshFailure;
    }

    private JwkKeys currentAfterRefreshFailure(JwkSetState current) {
        return current.refreshFailure() == null
                ? current.keys()
                : staleOrThrow(current.keys(), current.refreshFailure());
    }

    private JwkKeys publishedOutcome(JwkSetState published) {
        if (published.keys() != null) {
            return currentAfterRefreshFailure(published);
        }
        RuntimeException refreshFailure = published.refreshFailure();
        if (refreshFailure != null) {
            throw refreshFailure;
        }
        throw new IllegalStateException("JWK Set load produced no outcome");
    }

    private void recordRefreshFailure(RuntimeException refreshFailure) {
        JwkSetState current = state;
        state = new JwkSetState(current.keys(), current.lastLoad(), clock.instant(), refreshFailure);
    }

    private void cacheJwkKeys(JwkKeys loaded) {
        Instant now = clock.instant();
        state = new JwkSetState(loaded, now, now, null);
    }

    private boolean unknownKeyIdRefreshAllowed() {
        Instant lastLoad = state.lastLoad();
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

    private boolean refreshIntervalElapsed(JwkSetState current) {
        Instant lastRefresh = current.lastAttempt();
        if (lastRefresh == null) {
            return false;
        }
        return config.refreshInterval()
                .map(interval -> !clock.instant().isBefore(lastRefresh.plus(interval)))
                .orElse(false);
    }

    private boolean refreshRequired(JwkSetState current) {
        return current.refreshFailure() == null
                ? refreshIntervalElapsed(current)
                : failureRetryIntervalElapsed(current);
    }

    private boolean failureRetryIntervalElapsed(JwkSetState current) {
        Instant lastAttempt = current.lastAttempt();
        return lastAttempt == null
                || !clock.instant().isBefore(lastAttempt.plus(config.failureRetryInterval()));
    }

    static final class UnavailableException extends IllegalStateException {
        private UnavailableException() {
            super(Thread.currentThread().isInterrupted()
                          ? "Interrupted while waiting for JWK Set loading"
                          : "JWK Set loading capacity or admission timeout exceeded");
        }
    }

    private record JwkSetState(JwkKeys keys,
                               Instant lastLoad,
                               Instant lastAttempt,
                               RuntimeException refreshFailure) {
        private static JwkSetState empty() {
            return new JwkSetState(null, null, null, null);
        }
    }
}
