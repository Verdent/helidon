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

/**
 * Acquires and reuses outbound RFC 8693 Token Exchange access tokens.
 * <p>
 * The cache key covers the tenant, subject token identity, scope, resource, and audience. Only a SHA-256 digest of the
 * subject token is retained in the key; the raw credential is passed to the elected loader but is not retained by the
 * cache. The underlying cache is bounded and process-local, and concurrent requests for the same complete key share one
 * Token Endpoint operation while requests for different keys remain independent.
 */
final class OidcTokenExchangeTokenManager {
    private final OidcSingleFlightCache<CacheKey, CachedToken, OidcTokenExchangeResult> tokens =
            new OidcSingleFlightCache<>();

    OidcTokenExchangeResult token(OidcTenantContext tenantContext,
                                  OidcOutboundPolicy policy,
                                  String subjectToken,
                                  Instant now) {
        CacheKey cacheKey = new CacheKey(tenantContext.tenantId(),
                                         tokenHash(subjectToken),
                                         policy.tokenExchangeScope().orElse(""),
                                         policy.tokenExchangeResource().orElse(""),
                                         policy.tokenExchangeAudience().orElse(""));
        Duration clockSkew = tenantContext.tokenValidation().clockSkew();
        return tokens.resolve(cacheKey,
                              cachedToken -> cachedToken.activeAt(now, clockSkew),
                              cachedToken -> OidcTokenExchangeResult.success(cachedToken.tokenResponse()),
                              () -> loadToken(tenantContext, policy, subjectToken, now, clockSkew));
    }

    private OidcSingleFlightCache.Resolution<CachedToken, OidcTokenExchangeResult> loadToken(
            OidcTenantContext tenantContext,
            OidcOutboundPolicy policy,
            String subjectToken,
            Instant now,
            Duration clockSkew) {
        OidcTokenExchangeResult result = tenantContext.endpointClient()
                .tokenExchange(subjectToken,
                               policy.tokenExchangeScope(),
                               policy.tokenExchangeResource(),
                               policy.tokenExchangeAudience());
        if (!result.succeeded()) {
            // Share this endpoint result with current waiters, but allow a later request to retry.
            return OidcSingleFlightCache.Resolution.doNotCache(result);
        }

        OidcTokenExchangeResponse tokenResponse = result.tokenResponse().orElseThrow();
        Optional<Long> expiresIn = tokenResponse.expiresIn().filter(value -> value > 0);
        if (expiresIn.isEmpty()) {
            // Without a positive lifetime, there is no defensible interval in which this token can be reused.
            return OidcSingleFlightCache.Resolution.doNotCache(result);
        }

        CachedToken cachedToken = new CachedToken(tokenResponse, now.plusSeconds(expiresIn.orElseThrow()));
        return cachedToken.activeAt(now, clockSkew)
                ? OidcSingleFlightCache.Resolution.cache(cachedToken, result)
                : OidcSingleFlightCache.Resolution.doNotCache(result);
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
