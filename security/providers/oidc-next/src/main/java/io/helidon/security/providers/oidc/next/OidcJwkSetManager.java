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

import io.helidon.common.configurable.ResourceConfig;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.WebClient;

final class OidcJwkSetManager {
    private static final Duration DEFAULT_REMOTE_REFRESH_INTERVAL = Duration.ofMinutes(5);

    private final String tenantId;
    private final Optional<URI> jwkSetUri;
    private final boolean remoteHttp;
    private final OidcJwkSetConfig config;
    private final Function<Boolean, OidcJwkSetLoader.LoadedJwkSet> keyLoader;
    private final Clock clock;
    private final OidcRemoteWorkLimiter refreshAdmission;
    private volatile JwkSetState state = JwkSetState.empty();
    private Instant lastUnknownKeyIdRefreshAttempt;

    private OidcJwkSetManager(String tenantId,
                              Optional<URI> jwkSetUri,
                              OidcJwkSetConfig config,
                              Function<Boolean, OidcJwkSetLoader.LoadedJwkSet> keyLoader,
                              Clock clock) {
        this.tenantId = tenantId;
        this.jwkSetUri = jwkSetUri;
        this.remoteHttp = jwkSetUri.map(URI::getScheme)
                .map(scheme -> "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                .orElse(false);
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
        OidcJwkSetLoader loader = new OidcJwkSetLoader(webClient, unauthorizedJwkSetAccessToken, clock);
        Optional<URI> uri = metadata.jwkSetUri();
        return new OidcJwkSetManager(tenantId, uri, config,
                                    revalidate -> loader.load(uri.orElseThrow(() -> new IllegalStateException(
                                            "JWK Set URI is not configured for tenant: "
                                                    + OidcDiagnostics.sanitizeLogValue(tenantId))), revalidate), clock);
    }

    static OidcJwkSetManager createLocal(String tenantId,
                                         ResourceConfig verificationJwk,
                                         Clock clock,
                                         OidcJwkSetConfig config) {
        return new OidcJwkSetManager(tenantId, Optional.empty(), config,
                                    _ -> OidcJwkSetLoader.loadLocal(verificationJwk), clock);
    }

    static OidcJwkSetManager createRemote(String tenantId,
                                          URI jwkSetUri,
                                          WebClient webClient,
                                          Clock clock,
                                          OidcJwkSetConfig config) {
        // Independent access-token keys must not inherit the OP adapter's credentials for its own JWK Set URI.
        OidcJwkSetLoader loader = new OidcJwkSetLoader(webClient, _ -> Optional.empty(), clock);
        return new OidcJwkSetManager(tenantId, Optional.of(jwkSetUri), config,
                                    revalidate -> loader.load(jwkSetUri, revalidate), clock);
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
        JwkSetState before = state;
        JwkKeys current = jwkKeys();
        JwkKeys availableKeys = current;
        Optional<String> unknownKeyId = keyId.filter(kid -> availableKeys.forKeyId(kid).isEmpty());
        if (unknownKeyId.isEmpty()) {
            return current;
        }
        JwkSetState observed = state;
        if (before != observed) {
            // The current request already loaded or refreshed the keys. Do not fetch twice for one unfamiliar kid.
            if (observed.refreshFailure() != null) {
                throw observed.refreshFailure();
            }
            // Another caller may have published the missing key since our lookup began.
            return observed.keys() != null ? observed.keys() : current;
        }
        return refreshUnknownKeyId(unknownKeyId.orElseThrow(), current, observed);
    }

    private OidcJwkSetLoader.LoadedJwkSet loadJwkKeys(boolean revalidate) {
        try {
            return keyLoader.apply(revalidate);
        } catch (RuntimeException e) {
            throw new UnavailableException("Failed to load JWK Set for tenant: "
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
            return refreshJwkKeys(current);
        }
    }

    private JwkKeys refreshUnknownKeyId(String keyId, JwkKeys staleKeys, JwkSetState observed) {
        if (!config.unknownKeyIdRefreshEnabled()) {
            return staleKeys;
        }
        try (OidcRemoteWorkLimiter.Permit _ = acquireRefresh()) {
            JwkSetState currentState = state;
            if (currentState != observed) {
                if (currentState.refreshFailure() != null) {
                    throw currentState.refreshFailure();
                }
                return publishedOutcome(currentState);
            }
            JwkKeys current = currentState.keys();
            if (current == null) {
                return loadInitialJwkKeys(currentState);
            }
            if (current.forKeyId(keyId).isPresent()) {
                return current;
            }
            if (currentState.refreshFailure() != null && !failureRetryIntervalElapsed(currentState)) {
                throw currentState.refreshFailure();
            }
            if (!unknownKeyIdRefreshAllowed()) {
                if (currentState.refreshFailure() != null) {
                    throw currentState.refreshFailure();
                }
                return currentAfterRefreshFailure(currentState);
            }
            try {
                OidcJwkSetLoader.LoadedJwkSet loaded = loadJwkKeys(true);
                cacheJwkKeys(loaded);
                return loaded.keys();
            } catch (RuntimeException e) {
                recordRefreshFailure(e);
                // Cached keys cannot verify this kid, even when stale use is permitted for known keys.
                throw e;
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
            return refreshRequired(current) ? refreshJwkKeys(current) : currentAfterRefreshFailure(current);
        }
        if (current.refreshFailure() != null && !failureRetryIntervalElapsed(current)) {
            throw current.refreshFailure();
        }
        try {
            return refreshJwkKeys(false);
        } catch (RuntimeException e) {
            recordRefreshFailure(e);
            throw e;
        }
    }

    private JwkKeys refreshJwkKeys(boolean revalidate) {
        OidcJwkSetLoader.LoadedJwkSet loaded = loadJwkKeys(revalidate);
        cacheJwkKeys(loaded);
        return loaded.keys();
    }

    private JwkKeys refreshJwkKeys(JwkSetState current) {
        try {
            return refreshJwkKeys(true);
        } catch (RuntimeException e) {
            recordRefreshFailure(e);
            return staleOrThrow(current, e);
        }
    }

    private JwkKeys staleOrThrow(JwkSetState current, RuntimeException refreshFailure) {
        if (current.staleUntil() != null && clock.instant().isBefore(current.staleUntil())) {
            return current.keys();
        }
        throw refreshFailure;
    }

    private JwkKeys currentAfterRefreshFailure(JwkSetState current) {
        return current.refreshFailure() == null || !expired(current)
                ? current.keys()
                : staleOrThrow(current, current.refreshFailure());
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
        state = new JwkSetState(current.keys(), clock.instant(), current.expiresAt(), current.staleUntil(), refreshFailure);
    }

    private void cacheJwkKeys(OidcJwkSetLoader.LoadedJwkSet loaded) {
        Instant now = clock.instant();
        Duration configuredLifetime = config.refreshInterval()
                .orElse(remoteHttp ? DEFAULT_REMOTE_REFRESH_INTERVAL : null);
        Instant expiresAt = null;
        if (configuredLifetime != null) {
            if (remoteHttp && loaded.responseAge().compareTo(configuredLifetime) > 0
                    && loaded.responseAge().minus(configuredLifetime).compareTo(Duration.ofSeconds(1)) >= 0) {
                throw new UnavailableException("JWK Set response exceeds the configured maximum age", null);
            }
            Duration localRemaining = loaded.responseAge().compareTo(configuredLifetime) >= 0
                    ? Duration.ZERO : configuredLifetime.minus(loaded.responseAge());
            Duration lifetime = loaded.freshness()
                    .map(freshness -> freshness.compareTo(localRemaining) < 0 ? freshness : localRemaining)
                    .orElse(localRemaining);
            expiresAt = now.plus(lifetime);
        }
        Instant staleUntil = null;
        if (expiresAt != null && loaded.staleAllowed() && !config.maxStaleOnError().isZero()) {
            Duration permitted = loaded.staleIfError()
                    .map(issuerLimit -> issuerLimit.compareTo(config.maxStaleOnError()) < 0
                            ? issuerLimit : config.maxStaleOnError())
                    .orElse(config.maxStaleOnError());
            staleUntil = expiresAt.plus(permitted);
        }
        state = new JwkSetState(loaded.keys(), now, expiresAt, staleUntil, null);
    }

    private boolean unknownKeyIdRefreshAllowed() {
        Instant now = clock.instant();
        Duration refreshInterval = config.unknownKeyIdRefreshInterval();
        Instant lastAttempt = lastUnknownKeyIdRefreshAttempt;
        if (lastAttempt != null && now.isBefore(lastAttempt.plus(refreshInterval))) {
            return false;
        }
        lastUnknownKeyIdRefreshAttempt = now;
        return true;
    }

    private boolean expired(JwkSetState current) {
        return current.expiresAt() != null && !clock.instant().isBefore(current.expiresAt());
    }

    private boolean refreshRequired(JwkSetState current) {
        return expired(current) && (current.refreshFailure() == null || failureRetryIntervalElapsed(current));
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

        private UnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private record JwkSetState(JwkKeys keys,
                               Instant lastAttempt,
                               Instant expiresAt,
                               Instant staleUntil,
                               RuntimeException refreshFailure) {
        private static JwkSetState empty() {
            return new JwkSetState(null, null, null, null, null);
        }
    }
}
