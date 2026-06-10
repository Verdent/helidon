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
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

final class OidcClientCredentialsTokenManager {
    private final ConcurrentMap<CacheKey, CachedToken> tokens = new ConcurrentHashMap<>();

    OidcTokenEndpointResult token(OidcTenantContext tenantContext,
                                  Optional<String> scope,
                                  List<String> resources,
                                  Instant now) {
        List<String> resourceList = List.copyOf(resources);
        CacheKey cacheKey = new CacheKey(tenantContext.tenantId(), scope.orElse(""), resourceList);
        Duration clockSkew = tenantContext.tokenValidation().clockSkew();
        CachedToken cachedToken = tokens.get(cacheKey);
        if (cachedToken != null && cachedToken.activeAt(now, clockSkew)) {
            return OidcTokenEndpointResult.success(cachedToken.tokenResponse());
        }

        OidcTokenEndpointResult result = tenantContext.endpointClient().clientCredentialsToken(scope, resourceList);
        if (!result.succeeded()) {
            return result;
        }

        OidcTokenResponse tokenResponse = result.tokenResponse().orElseThrow();
        Optional<Long> expiresIn = tokenResponse.expiresIn()
                .filter(value -> value > 0);
        if (expiresIn.isEmpty()) {
            tokens.remove(cacheKey);
            return result;
        }

        CachedToken newCachedToken = new CachedToken(tokenResponse, now.plusSeconds(expiresIn.orElseThrow()));
        if (newCachedToken.activeAt(now, clockSkew)) {
            tokens.put(cacheKey, newCachedToken);
        } else {
            tokens.remove(cacheKey);
        }
        return result;
    }

    private record CacheKey(String tenantId, String scope, List<String> resources) {
    }

    private record CachedToken(OidcTokenResponse tokenResponse, Instant expiresAt) {
        private boolean activeAt(Instant now, Duration clockSkew) {
            return expiresAt.minus(clockSkew).isAfter(now);
        }
    }
}
