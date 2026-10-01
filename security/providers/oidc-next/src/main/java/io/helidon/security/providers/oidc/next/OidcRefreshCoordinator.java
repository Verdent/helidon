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

import java.time.Instant;
import java.util.Objects;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Coordinates refresh-token work for one tenant runtime.
 * <p>
 * The first caller for a source local-authentication session performs the refresh while admitted same-session callers
 * wait interruptibly for its result. Completed outcomes remain available for a short, capacity-bounded grace interval
 * so a request which reaches refresh just after the leader completes does not redeem an invalidated rotating token.
 * <p>
 * No raw token is retained as a coordination key. The key also includes source-session creation and browser generation,
 * preventing a later state which retains a non-rotating refresh token from reusing an earlier refresh outcome.
 *
 * @param <R> refresh result type
 */
final class OidcRefreshCoordinator<R> {
    private final OidcSingleFlightCache<RefreshKey, CachedResult<R>, R> outcomes;
    private final OidcRemoteWorkLimiter remoteWorkLimiter;
    private final long resultRetentionNanos;
    private final LongSupplier nanoTime;

    OidcRefreshCoordinator(OidcAuthorizationCodeConfig config) {
        this(config, System::nanoTime);
    }

    OidcRefreshCoordinator(OidcAuthorizationCodeConfig config, LongSupplier nanoTime) {
        this.outcomes = new OidcSingleFlightCache<>(config.refreshResultCacheCapacity());
        this.remoteWorkLimiter = new OidcRemoteWorkLimiter(config.refreshRemoteWork());
        this.resultRetentionNanos = config.refreshResultRetention().toNanos();
        this.nanoTime = Objects.requireNonNull(nanoTime);
    }

    R resolve(OidcLocalAuthenticationResult source,
              Predicate<R> reusable,
              Supplier<R> refresh,
              Supplier<R> rejected) {
        Objects.requireNonNull(source);
        Objects.requireNonNull(reusable);
        Objects.requireNonNull(refresh);
        Objects.requireNonNull(rejected);
        String refreshToken = source.refreshToken().orElseThrow();
        RefreshKey key = new RefreshKey(source.browserSessionGeneration()
                                                .map(OidcTokenFingerprint::sha256)
                                                .orElse(""),
                                        source.createdAt(),
                                        OidcTokenFingerprint.sha256(source.idToken().rawToken()),
                                        OidcTokenFingerprint.sha256(source.accessToken()),
                                        OidcTokenFingerprint.sha256(refreshToken));
        return outcomes.resolve(key,
                                cached -> cached.reusableAt(nanoTime.getAsLong(), resultRetentionNanos)
                                        && reusable.test(cached.result()),
                                CachedResult::result,
                                () -> completed(refresh),
                                remoteWorkLimiter,
                                rejected);
    }

    int cachedResultCount() {
        return outcomes.size();
    }

    OidcRemoteWorkLimiter remoteWorkLimiter() {
        return remoteWorkLimiter;
    }

    private OidcSingleFlightCache.Resolution<CachedResult<R>, R> completed(Supplier<R> refresh) {
        R result = Objects.requireNonNull(refresh.get());
        CachedResult<R> cached = new CachedResult<>(result, nanoTime.getAsLong());
        return OidcSingleFlightCache.Resolution.cache(cached, result);
    }

    private record RefreshKey(String browserSessionGenerationFingerprint,
                              Instant sourceCreatedAt,
                              String idTokenFingerprint,
                              String accessTokenFingerprint,
                              String refreshTokenFingerprint) {
    }

    private record CachedResult<R>(R result, long completedAtNanos) {
        private CachedResult {
            result = Objects.requireNonNull(result);
        }

        private boolean reusableAt(long nowNanos, long retentionNanos) {
            long age = nowNanos - completedAtNanos;
            return age >= 0 && age < retentionNanos;
        }
    }
}
