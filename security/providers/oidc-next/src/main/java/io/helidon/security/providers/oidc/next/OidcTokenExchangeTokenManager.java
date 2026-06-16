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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

final class OidcTokenExchangeTokenManager {
    private final ConcurrentMap<CacheKey, CachedToken> tokens = new ConcurrentHashMap<>();

    OidcTokenExchangeResult token(OidcTenantContext tenantContext,
                                  OidcOutboundPolicy policy,
                                  String subjectToken,
                                  Instant now) {
        CacheKey cacheKey = new CacheKey(tenantContext.tenantId(),
                                         tokenHash(subjectToken),
                                         OidcTokenExchangeResponse.ACCESS_TOKEN_TYPE,
                                         OidcTokenExchangeResponse.ACCESS_TOKEN_TYPE,
                                         policy.tokenExchangeScope().orElse(""),
                                         policy.tokenExchangeResource().orElse(""),
                                         policy.tokenExchangeAudience().orElse(""));
        Duration clockSkew = tenantContext.tokenValidation().clockSkew();
        CachedToken cachedToken = tokens.get(cacheKey);
        if (cachedToken != null && cachedToken.activeAt(now, clockSkew)) {
            return OidcTokenExchangeResult.success(cachedToken.tokenResponse());
        }

        OidcTokenExchangeResult result = tenantContext.endpointClient()
                .tokenExchange(subjectToken,
                               policy.tokenExchangeScope(),
                               policy.tokenExchangeResource(),
                               policy.tokenExchangeAudience());
        if (!result.succeeded()) {
            return result;
        }

        OidcTokenExchangeResponse tokenResponse = result.tokenResponse().orElseThrow();
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

    private static String tokenHash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest is not available", e);
        }
    }

    private record CacheKey(String tenantId,
                            String subjectTokenHash,
                            String subjectTokenType,
                            String requestedTokenType,
                            String scope,
                            String resource,
                            String audience) {
    }

    private record CachedToken(OidcTokenExchangeResponse tokenResponse, Instant expiresAt) {
        private boolean activeAt(Instant now, Duration clockSkew) {
            return expiresAt.minus(clockSkew).isAfter(now);
        }
    }
}
