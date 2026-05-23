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
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

final class OidcClientCredentialsTokenManager {
    private final ConcurrentMap<String, CachedToken> tokens = new ConcurrentHashMap<>();

    OidcTokenEndpointResult token(OidcTenantContext tenantContext, Instant now) {
        Duration clockSkew = tenantContext.tokenValidation().clockSkew();
        CachedToken cachedToken = tokens.get(tenantContext.tenantId());
        if (cachedToken != null && cachedToken.activeAt(now, clockSkew)) {
            return OidcTokenEndpointResult.success(cachedToken.tokenResponse());
        }

        OidcTokenEndpointResult result = tenantContext.endpointClient().clientCredentialsToken();
        if (!result.succeeded()) {
            return result;
        }

        OidcTokenResponse tokenResponse = result.tokenResponse().orElseThrow();
        Optional<Long> expiresIn = tokenResponse.expiresIn()
                .filter(value -> value > 0);
        if (expiresIn.isEmpty()) {
            tokens.remove(tenantContext.tenantId());
            return result;
        }

        CachedToken newCachedToken = new CachedToken(tokenResponse, now.plusSeconds(expiresIn.orElseThrow()));
        if (newCachedToken.activeAt(now, clockSkew)) {
            tokens.put(tenantContext.tenantId(), newCachedToken);
        } else {
            tokens.remove(tenantContext.tenantId());
        }
        return result;
    }

    private record CachedToken(OidcTokenResponse tokenResponse, Instant expiresAt) {
        private boolean activeAt(Instant now, Duration clockSkew) {
            return expiresAt.minus(clockSkew).isAfter(now);
        }
    }
}
