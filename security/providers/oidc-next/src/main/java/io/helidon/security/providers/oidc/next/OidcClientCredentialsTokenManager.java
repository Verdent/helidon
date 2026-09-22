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

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Acquires and reuses outbound Client Credentials access tokens.
 * <p>
 * The cache key includes every input that can change the authority or requested access: tenant, scope, and ordered
 * resource indicators. The underlying cache is bounded and process-local, and concurrent requests for the same key
 * share one Token Endpoint operation. Requests for different keys remain independent.
 * <p>
 * The Token Endpoint client supplier is invoked only by the elected loader after both cache lookups. A reusable token
 * therefore bypasses deferred endpoint discovery and metadata validation entirely.
 */
final class OidcClientCredentialsTokenManager {
    private final OidcSingleFlightCache<CacheKey, CachedToken, OidcTokenEndpointResult> tokens =
            new OidcSingleFlightCache<>();

    OidcTokenEndpointResult token(OidcTenantContext tenantContext,
                                  Optional<String> scope,
                                  List<String> resources,
                                  Instant now,
                                  OidcRemoteWorkLimiter remoteWorkLimiter,
                                  Supplier<OidcEndpointClient> endpointClientSupplier) {
        List<String> resourceList = List.copyOf(resources);
        CacheKey cacheKey = new CacheKey(tenantContext.tenantId(), scope.orElse(""), resourceList);
        Duration clockSkew = tenantContext.tokenValidation().clockSkew();
        return tokens.resolve(cacheKey,
                              cachedToken -> cachedToken.activeAt(now, clockSkew),
                              cachedToken -> OidcTokenEndpointResult.success(cachedToken.tokenResponse()),
                              () -> loadToken(endpointClientSupplier, scope, resourceList, now, clockSkew),
                              remoteWorkLimiter,
                              () -> OidcTokenEndpointResult.failure(Thread.currentThread().isInterrupted()
                                          ? "Interrupted while waiting for Client Credentials Grant"
                                          : "Client Credentials Grant capacity or admission timeout exceeded"));
    }

    private OidcSingleFlightCache.Resolution<CachedToken, OidcTokenEndpointResult> loadToken(
            Supplier<OidcEndpointClient> endpointClientSupplier,
            Optional<String> scope,
            List<String> resources,
            Instant now,
            Duration clockSkew) {
        OidcEndpointClient endpointClient = Objects.requireNonNull(endpointClientSupplier.get());
        OidcTokenEndpointResult result = endpointClient.clientCredentialsToken(scope, resources);
        if (!result.succeeded()) {
            // Share this endpoint result with current waiters, but allow a later request to retry.
            return OidcSingleFlightCache.Resolution.doNotCache(result);
        }

        OidcTokenResponse tokenResponse = result.tokenResponse().orElseThrow();
        Optional<Long> expiresIn = tokenResponse.expiresIn();
        if (expiresIn.isEmpty()) {
            // Without an explicit lifetime, there is no defensible interval in which this token can be reused.
            return OidcSingleFlightCache.Resolution.doNotCache(result);
        }

        CachedToken cachedToken = new CachedToken(tokenResponse, OidcTokenLifetime.expiresAt(now, expiresIn.orElseThrow()));
        return cachedToken.activeAt(now, clockSkew)
                ? OidcSingleFlightCache.Resolution.cache(cachedToken, result)
                : OidcSingleFlightCache.Resolution.doNotCache(result);
    }

    private record CacheKey(String tenantId, String scope, List<String> resources) {
    }

    private record CachedToken(OidcTokenResponse tokenResponse, Instant expiresAt) {
        private boolean activeAt(Instant now, Duration clockSkew) {
            return OidcTokenLifetime.activeAt(expiresAt, now, clockSkew);
        }
    }
}
