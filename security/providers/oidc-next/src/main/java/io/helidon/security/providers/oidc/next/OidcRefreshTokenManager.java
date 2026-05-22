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

final class OidcRefreshTokenManager {
    private static final System.Logger LOGGER = System.getLogger(OidcRefreshTokenManager.class.getName());

    private OidcRefreshTokenManager() {
    }

    static OidcRefreshTokenManager create() {
        return new OidcRefreshTokenManager();
    }

    RefreshResult refreshIfNeeded(OidcLocalAuthenticationResult authenticationResult,
                                  OidcTenantContext tenantContext,
                                  Instant now) {
        Optional<Instant> accessTokenExpiresAt = authenticationResult.accessTokenExpiresAt();
        if (accessTokenExpiresAt.isEmpty()) {
            return RefreshResult.authenticated(authenticationResult);
        }

        Instant expiresAt = accessTokenExpiresAt.orElseThrow();
        if (!refreshNeeded(expiresAt, tenantContext.tokenValidation().clockSkew(), now)) {
            return RefreshResult.authenticated(authenticationResult);
        }

        Optional<String> refreshToken = authenticationResult.refreshToken();
        if (refreshToken.isEmpty()) {
            return accessTokenExpired(expiresAt, now)
                    ? RefreshResult.removeLocalAuthentication()
                    : RefreshResult.authenticated(authenticationResult);
        }

        OidcTokenEndpointResult tokenResult = tenantContext.endpointClient()
                .refreshAccessToken(refreshToken.orElseThrow());
        if (tokenResult.succeeded()) {
            OidcTokenResponse tokenResponse = tokenResult.tokenResponse().orElseThrow();
            if (tokenResponse.expiresIn().isEmpty()) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "Token Endpoint refresh response did not include expires_in");
                return accessTokenExpired(expiresAt, now)
                        ? RefreshResult.removeLocalAuthentication()
                        : RefreshResult.authenticated(authenticationResult);
            }
            return RefreshResult.refreshed(refresh(authenticationResult,
                                                 tokenResponse,
                                                 now));
        }

        logRefreshFailure(tokenResult);
        if (invalidGrant(tokenResult) || accessTokenExpired(expiresAt, now)) {
            return RefreshResult.removeLocalAuthentication();
        }
        return RefreshResult.authenticated(authenticationResult);
    }

    private OidcLocalAuthenticationResult refresh(OidcLocalAuthenticationResult current,
                                                  OidcTokenResponse tokenResponse,
                                                  Instant refreshedAt) {
        /*
         * Spec: RFC 6749, 6 Refreshing an Access Token
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-6
         * Quotes: "if omitted is treated as equal to the scope originally granted by the resource owner";
         * "The authorization server MAY issue a new refresh token, in which case the client MUST discard the old
         * refresh token and replace it with the new refresh token".
         */
        return OidcLocalAuthenticationResult.create(
                current.tenantId(),
                current.idToken(),
                tokenResponse.accessToken(),
                tokenResponse.tokenType(),
                tokenResponse.refreshToken()
                        .or(() -> current.refreshToken())
                        .orElse(null),
                tokenResponse.scope()
                        .or(() -> current.scope())
                        .orElse(null),
                refreshedAt,
                current.expiresAt(),
                tokenResponse.expiresIn()
                        .map(refreshedAt::plusSeconds)
                        .orElse(null));
    }

    private boolean refreshNeeded(Instant expiresAt, Duration skew, Instant now) {
        return accessTokenExpired(expiresAt, now) || !now.plus(skew).isBefore(expiresAt);
    }

    private boolean accessTokenExpired(Instant expiresAt, Instant now) {
        return !now.isBefore(expiresAt);
    }

    private void logRefreshFailure(OidcTokenEndpointResult tokenResult) {
        tokenResult.cause()
                .ifPresentOrElse(cause -> LOGGER.log(System.Logger.Level.DEBUG,
                                                      tokenResult.description(),
                                                      cause),
                                 () -> LOGGER.log(System.Logger.Level.DEBUG,
                                                  tokenResult.description()));
    }

    private boolean invalidGrant(OidcTokenEndpointResult tokenResult) {
        /*
         * Spec: RFC 6749, 5.2 Error Response
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
         * Quote: "`invalid_grant` The provided authorization grant (e.g., authorization code, resource owner
         * credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the
         * authorization request, or was issued to another client".
         */
        return tokenResult.error()
                .map(OidcTokenErrorResponse::error)
                .filter("invalid_grant"::equals)
                .isPresent();
    }

    record RefreshResult(Optional<OidcLocalAuthenticationResult> authenticationResult,
                         boolean refreshed,
                         boolean removeCookie) {
        private static RefreshResult authenticated(OidcLocalAuthenticationResult authenticationResult) {
            return new RefreshResult(Optional.of(authenticationResult), false, false);
        }

        private static RefreshResult refreshed(OidcLocalAuthenticationResult authenticationResult) {
            return new RefreshResult(Optional.of(authenticationResult), true, false);
        }

        private static RefreshResult removeLocalAuthentication() {
            return new RefreshResult(Optional.empty(), false, true);
        }
    }
}
