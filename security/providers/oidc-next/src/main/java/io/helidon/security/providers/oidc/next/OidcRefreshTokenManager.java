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
import java.util.Map;
import java.util.Optional;

import io.helidon.json.JsonObject;

final class OidcRefreshTokenManager {
    private static final System.Logger LOGGER = System.getLogger(OidcRefreshTokenManager.class.getName());

    private final OidcIdTokenValidator idTokenValidator;
    private final Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators;

    OidcRefreshTokenManager(Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators) {
        this(new OidcIdTokenValidator(), accessTokenValidators);
    }

    private OidcRefreshTokenManager(OidcIdTokenValidator idTokenValidator,
                                    Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators) {
        this.idTokenValidator = idTokenValidator;
        this.accessTokenValidators = accessTokenValidators;
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
            return keepOrRemoveLocalAuthentication(authenticationResult, expiresAt, now);
        }

        OidcTokenEndpointResult tokenResult = tenantContext.endpointClient()
                .refreshAccessToken(refreshToken.orElseThrow());
        if (tokenResult.succeeded()) {
            OidcTokenResponse tokenResponse = tokenResult.tokenResponse().orElseThrow();
            if (tokenResponse.expiresIn().isEmpty()) {
                return refreshFailure(authenticationResult,
                                      expiresAt,
                                      now,
                                      "Token Endpoint refresh response did not include expires_in",
                                      Optional.empty());
            }
            Optional<OidcTokenValidationMethod> validationMethod = tenantContext.tokenValidation().method();
            if (validationMethod.isPresent()) {
                OidcAccessTokenValidator accessTokenValidator = accessTokenValidators.get(
                        validationMethod.orElseThrow());
                if (accessTokenValidator == null) {
                    return refreshFailure(authenticationResult,
                                          expiresAt,
                                          now,
                                          "Refreshed access token validation is not implemented for method: "
                                                  + validationMethod.orElseThrow(),
                                          Optional.empty());
                }
                OidcValidationResult<OidcValidatedAccessToken> accessTokenValidationResult =
                        accessTokenValidator.validate(OidcAccessTokenValidationRequest
                                                              .refreshedAuthorizationCodeAccessToken(
                                                                      tokenResponse.accessToken(),
                                                                      tenantContext));
                if (!accessTokenValidationResult.succeeded()) {
                    return refreshFailure(authenticationResult,
                                          expiresAt,
                                          now,
                                          accessTokenValidationResult.errorDescription()
                                                  .orElse("Refreshed access token validation failed"),
                                          accessTokenValidationResult.cause());
                }
            }

            OidcValidatedIdToken idToken = authenticationResult.idToken();
            Optional<String> refreshedIdToken = tokenResponse.idToken();
            if (refreshedIdToken.isPresent()) {
                OidcValidationResult<OidcValidatedIdToken> idTokenValidationResult =
                        idTokenValidator.validateRefresh(refreshedIdToken.orElseThrow(),
                                                         tenantContext,
                                                         authenticationResult.idToken());
                if (!idTokenValidationResult.succeeded()) {
                    return refreshFailure(authenticationResult,
                                          expiresAt,
                                          now,
                                          idTokenValidationResult.errorDescription()
                                                  .orElse("Refreshed ID Token validation failed"),
                                          idTokenValidationResult.cause());
                }
                idToken = idTokenValidationResult.validatedToken().orElseThrow();
            }

            OidcUserInfoSupport.Result userInfoResult = OidcUserInfoSupport.userInfo(tenantContext,
                                                                                      tokenResponse.accessToken(),
                                                                                      idToken);
            if (!userInfoResult.succeeded()) {
                return refreshFailure(authenticationResult,
                                      expiresAt,
                                      now,
                                      userInfoResult.errorDescription().orElseThrow() + " during refresh",
                                      Optional.empty());
            }

            return RefreshResult.refreshed(refresh(authenticationResult,
                                                 tokenResponse,
                                                 idToken,
                                                 userInfoResult.userInfo(),
                                                 now));
        }

        logFailure(tokenResult.description(), tokenResult.cause());
        if (invalidGrant(tokenResult) || accessTokenExpired(expiresAt, now)) {
            return RefreshResult.removeLocalAuthentication();
        }
        return RefreshResult.authenticated(authenticationResult);
    }

    private RefreshResult refreshFailure(OidcLocalAuthenticationResult current,
                                         Instant expiresAt,
                                         Instant now,
                                         String description,
                                         Optional<Throwable> cause) {
        logFailure(description, cause);
        return keepOrRemoveLocalAuthentication(current, expiresAt, now);
    }

    private RefreshResult keepOrRemoveLocalAuthentication(OidcLocalAuthenticationResult current,
                                                          Instant expiresAt,
                                                          Instant now) {
        return accessTokenExpired(expiresAt, now)
                ? RefreshResult.removeLocalAuthentication()
                : RefreshResult.authenticated(current);
    }

    private OidcLocalAuthenticationResult refresh(OidcLocalAuthenticationResult current,
                                                  OidcTokenResponse tokenResponse,
                                                  OidcValidatedIdToken idToken,
                                                  Optional<JsonObject> userInfo,
                                                  Instant refreshedAt) {
        /*
         * Spec: RFC 6749, 6 Refreshing an Access Token
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-6
         * Quote: "`scope` OPTIONAL. The requested scope MUST NOT include any scope not originally granted by the
         * resource owner, and if omitted is treated as equal to the scope originally granted by the resource owner."
         * Quote: "The authorization server MAY issue a new refresh token, in which case the client MUST discard the
         * old refresh token and replace it with the new refresh token."
         */
        return OidcLocalAuthenticationResult.fromStoredValues(
                current.tenantId(),
                idToken,
                tokenResponse.accessToken(),
                tokenResponse.tokenType(),
                tokenResponse.refreshToken()
                        .or(() -> current.refreshToken()),
                tokenResponse.scope()
                        .or(() -> current.scope()),
                userInfo,
                refreshedAt,
                idToken.jwt()
                        .expirationTime()
                        .filter(expirationTime -> expirationTime.isBefore(current.expiresAt()))
                        .orElse(current.expiresAt()),
                tokenResponse.expiresIn()
                        .map(refreshedAt::plusSeconds));
    }

    private boolean refreshNeeded(Instant expiresAt, Duration skew, Instant now) {
        return accessTokenExpired(expiresAt, now) || !now.plus(skew).isBefore(expiresAt);
    }

    private boolean accessTokenExpired(Instant expiresAt, Instant now) {
        return !now.isBefore(expiresAt);
    }

    private void logFailure(String description, Optional<Throwable> cause) {
        if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
            LOGGER.log(System.Logger.Level.DEBUG,
                       "OIDC local authentication refresh failed: reason="
                               + OidcDiagnostics.sanitizeLogValue(description)
                               + ", cause=" + cause.map(OidcDiagnostics::safeExceptionType).orElse("<none>"));
        }
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
