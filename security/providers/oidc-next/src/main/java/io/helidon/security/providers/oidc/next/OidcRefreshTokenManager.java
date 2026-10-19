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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import io.helidon.json.JsonObject;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;

final class OidcRefreshTokenManager {
    private static final System.Logger LOGGER = System.getLogger(OidcRefreshTokenManager.class.getName());

    private final OidcIdTokenValidator idTokenValidator = new OidcIdTokenValidator();

    RefreshResult refreshIfNeeded(OidcLocalAuthenticationResult authenticationResult,
                                  OidcTenantContext tenantContext,
                                  Instant now,
                                  Map<String, List<String>> sourceCookies,
                                  boolean requested,
                                  Optional<OidcBackChannelLogoutStore> logoutStore) {
        Optional<Instant> accessTokenExpiresAt = authenticationResult.accessTokenExpiresAt();
        // RFC 6749 section 1.5 also permits obtaining additional access tokens with the original grant.
        // An explicit request therefore does not require a known access-token expiration time.
        if (!requested && (accessTokenExpiresAt.isEmpty()
                || OidcTokenLifetime.activeAt(accessTokenExpiresAt.orElseThrow(),
                                              now,
                                              OidcTokenLifetime.DEFAULT_ACCESS_TOKEN_RENEWAL_MARGIN))) {
            return RefreshResult.authenticated(authenticationResult);
        }

        Optional<String> refreshToken = authenticationResult.refreshToken();
        if (refreshToken.isEmpty()) {
            return keepOrRemoveLocalAuthentication(authenticationResult, accessTokenExpiresAt, now);
        }

        RefreshResult result = tenantContext.refreshCoordinator()
                .resolve(authenticationResult,
                         cachedResult -> cachedResult.authenticationActiveAt(now),
                         () -> refresh(authenticationResult,
                                       tenantContext,
                                       accessTokenExpiresAt,
                                       now,
                                       refreshToken.orElseThrow(),
                                       sourceCookies,
                                       logoutStore),
                         () -> refreshRejected(authenticationResult, accessTokenExpiresAt, now));
        return result.authenticationActiveAt(now) ? result : RefreshResult.serviceUnavailable();
    }

    private RefreshResult refresh(OidcLocalAuthenticationResult authenticationResult,
                                  OidcTenantContext tenantContext,
                                  Optional<Instant> accessTokenExpiresAt,
                                  Instant now,
                                  String refreshToken,
                                  Map<String, List<String>> sourceCookies,
                                  Optional<OidcBackChannelLogoutStore> logoutStore) {
        OidcTokenEndpointResult tokenResult = tenantContext.endpointClient()
                .refreshAccessToken(refreshToken);
        if (tokenResult.succeeded()) {
            OidcTokenResponse tokenResponse = tokenResult.tokenResponse().orElseThrow();
            // RFC 6749 section 5.1 recommends expires_in but does not require it. Preserve unknown access-token
            // expiry instead of treating a valid refresh response as an error or borrowing the ID Token's lifetime.
            // This RP is not the resource server for an arbitrary refreshed access token. Its issuer, keys, and
            // audience can differ from those configured for inbound API Bearer tokens. Keep it opaque; the validated
            // ID Token (and, when enabled, UserInfo subject binding) remains the source of browser identity.

            OidcValidatedIdToken idToken = authenticationResult.idToken();
            Optional<String> refreshedIdToken = tokenResponse.idToken();
            if (refreshedIdToken.isPresent()) {
                OidcValidationResult<OidcValidatedIdToken> idTokenValidationResult =
                        idTokenValidator.validateRefresh(refreshedIdToken.orElseThrow(),
                                                         tenantContext,
                                                         authenticationResult.idToken(),
                                                         now);
                if (!idTokenValidationResult.succeeded()) {
                    return refreshFailure(authenticationResult,
                                          accessTokenExpiresAt,
                                          now,
                                          idTokenValidationResult.errorDescription()
                                                  .orElse("Refreshed ID Token validation failed"),
                                          idTokenValidationResult.cause());
                }
                idToken = idTokenValidationResult.validatedToken().orElseThrow();
            }

            Optional<OidcBackChannelLogoutStore.Session> backChannelSession = authenticationResult.backChannelSession();
            if (logoutStore.isPresent()) {
                try {
                    if (refreshedIdToken.isPresent()) {
                        backChannelSession = Optional.of(OidcBackChannelSessionSupport.afterRefresh(
                                authenticationResult, idToken.jwt(), logoutStore.orElseThrow()));
                    } else if (OidcBackChannelSessionSupport.revoked(authenticationResult, logoutStore.orElseThrow())) {
                        return RefreshResult.removeLocalAuthentication();
                    }
                } catch (OidcBackChannelSessionSupport.SessionRevokedException _) {
                    return RefreshResult.removeLocalAuthentication();
                } catch (IllegalArgumentException | OidcBackChannelSessionSupport.StoreUnavailableException e) {
                    logFailure("Refreshed OP session cannot be verified for back-channel logout", Optional.of(e));
                    // A successful grant may have rotated the source refresh token. Never authenticate the old cookie
                    // or issue a replacement after revocation state becomes unavailable or its sid changes.
                    return RefreshResult.unavailableAfterRefresh();
                }
            }

            OidcUserInfoSupport.Result userInfoResult = OidcUserInfoSupport.userInfo(tenantContext,
                                                                                      tokenResponse.accessToken(),
                                                                                      idToken,
                                                                                      now);
            if (!userInfoResult.succeeded()) {
                return refreshFailure(authenticationResult,
                                      accessTokenExpiresAt,
                                      now,
                                      userInfoResult.diagnosticDescription().orElseThrow() + " during refresh",
                                      userInfoResult.cause());
            }

            OidcLocalAuthenticationResult refreshed = refresh(authenticationResult,
                                                               tokenResponse,
                                                               idToken,
                                                               userInfoResult.userInfo(),
                                                               now,
                                                               backChannelSession);
            try {
                return RefreshResult.refreshed(refreshed,
                                               tenantContext.cookieStateHandler()
                                                       .prepareLocalAuthenticationResult(refreshed, sourceCookies));
            } catch (OidcCookieStateHandler.SessionCookieException e) {
                logFailure("Refreshed OIDC session exceeds cookie storage capacity", Optional.of(e));
                return RefreshResult.unavailableAfterRefresh();
            }
        }

        logFailure(tokenResult.description(), tokenResult.cause());
        if (invalidGrant(tokenResult) || accessTokenExpired(accessTokenExpiresAt, now)) {
            return RefreshResult.removeLocalAuthentication();
        }
        return RefreshResult.authenticated(authenticationResult);
    }

    private RefreshResult refreshRejected(OidcLocalAuthenticationResult current,
                                          Optional<Instant> accessTokenExpiresAt,
                                          Instant now) {
        boolean interrupted = Thread.currentThread().isInterrupted();
        logFailure(interrupted
                           ? "Interrupted while waiting for local authentication refresh"
                           : "Local authentication refresh capacity is exhausted",
                   Optional.empty());
        return accessTokenExpired(accessTokenExpiresAt, now)
                ? RefreshResult.serviceUnavailable()
                : RefreshResult.authenticated(current);
    }

    private RefreshResult refreshFailure(OidcLocalAuthenticationResult current,
                                         Optional<Instant> accessTokenExpiresAt,
                                         Instant now,
                                         String description,
                                         Optional<Throwable> cause) {
        logFailure(description, cause);
        if (cause.filter(OidcJwkSetManager.UnavailableException.class::isInstance).isPresent()) {
            // The grant succeeded, but its issued tokens could not be validated. RFC 6749 section 6 permits rotation;
            // do not keep a possibly spent source refresh token or authenticate unvalidated replacement tokens.
            return RefreshResult.unavailableAfterRefresh();
        }
        return keepOrRemoveLocalAuthentication(current, accessTokenExpiresAt, now);
    }

    private RefreshResult keepOrRemoveLocalAuthentication(OidcLocalAuthenticationResult current,
                                                          Optional<Instant> accessTokenExpiresAt,
                                                          Instant now) {
        return accessTokenExpired(accessTokenExpiresAt, now)
                ? RefreshResult.removeLocalAuthentication()
                : RefreshResult.authenticated(current);
    }

    private OidcLocalAuthenticationResult refresh(OidcLocalAuthenticationResult current,
                                                  OidcTokenResponse tokenResponse,
                                                  OidcValidatedIdToken idToken,
                                                  Optional<JsonObject> userInfo,
                                                  Instant refreshedAt,
                                                  Optional<OidcBackChannelLogoutStore.Session> backChannelSession) {
        /*
         * Spec: RFC 6749, 6 Refreshing an Access Token
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-6
         * Quote: "`scope` OPTIONAL. The requested scope MUST NOT include any scope not originally granted by the
         * resource owner, and if omitted is treated as equal to the scope originally granted by the resource owner."
         * Quote: "The authorization server MAY issue a new refresh token, in which case the client MUST discard the
         * old refresh token and replace it with the new refresh token."
         */
        Instant expiresAt = idToken.jwt()
                .expirationTime()
                .filter(expirationTime -> expirationTime.isBefore(current.expiresAt()))
                .orElse(current.expiresAt());
        Optional<Instant> accessTokenExpiresAt = tokenResponse.expiresIn()
                .map(seconds -> OidcTokenLifetime.expiresAt(refreshedAt, seconds));
        Optional<OidcBackChannelLogoutStore.Session> updatedBackChannelSession = backChannelSession.map(session -> {
            OidcBackChannelLogoutStore.Identity original = session.identity();
            return new OidcBackChannelLogoutStore.Session(new OidcBackChannelLogoutStore.Identity(
                    original.tenantId(), original.issuer(), original.subject(), original.sid(),
                    expiresAt), session.marker());
        });
        OidcLocalAuthenticationState state = OidcLocalAuthenticationState.builder()
                .tenantId(current.tenantId())
                .idToken(idToken)
                .accessToken(tokenResponse.accessToken())
                .tokenType(tokenResponse.tokenType())
                .refreshToken(tokenResponse.refreshToken().or(current::refreshToken))
                .browserSessionGeneration(current.browserSessionGeneration())
                .scope(tokenResponse.scope().or(current::scope))
                .userInfo(userInfo)
                .createdAt(refreshedAt)
                .expiresAt(expiresAt)
                .accessTokenExpiresAt(accessTokenExpiresAt)
                .backChannelSession(updatedBackChannelSession)
                .buildPrototype();
        return OidcLocalAuthenticationResult.fromStoredValues(state);
    }

    private boolean accessTokenExpired(Optional<Instant> accessTokenExpiresAt, Instant now) {
        return accessTokenExpiresAt.filter(expiresAt -> !now.isBefore(expiresAt)).isPresent();
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

    static final class RefreshResult {
        private final Optional<OidcLocalAuthenticationResult> authenticationResult;
        private final Optional<OidcCookieStateHandler.PreparedCookies> preparedSession;
        private final Outcome outcome;

        private RefreshResult(Optional<OidcLocalAuthenticationResult> authenticationResult,
                              Optional<OidcCookieStateHandler.PreparedCookies> preparedSession,
                              Outcome outcome) {
            this.authenticationResult = Objects.requireNonNull(authenticationResult);
            this.preparedSession = Objects.requireNonNull(preparedSession);
            this.outcome = Objects.requireNonNull(outcome);
            boolean authenticationExpected = outcome == Outcome.AUTHENTICATED || outcome == Outcome.REFRESHED;
            if (authenticationResult.isPresent() != authenticationExpected) {
                throw new IllegalArgumentException("Refresh authentication result does not match outcome: " + outcome);
            }
            if (preparedSession.isPresent() != (outcome == Outcome.REFRESHED)) {
                throw new IllegalArgumentException("Prepared cookies do not match the refresh outcome");
            }
        }

        Optional<OidcCookieStateHandler.PreparedCookies> preparedSession() {
            return preparedSession;
        }

        Optional<OidcLocalAuthenticationResult> authenticationResult() {
            return authenticationResult;
        }

        boolean refreshed() {
            return outcome == Outcome.REFRESHED;
        }

        boolean removeCookie() {
            return outcome == Outcome.REMOVE_COOKIE || outcome == Outcome.UNAVAILABLE_REMOVE_COOKIE;
        }

        boolean unavailable() {
            return outcome == Outcome.UNAVAILABLE || outcome == Outcome.UNAVAILABLE_REMOVE_COOKIE;
        }

        private static RefreshResult authenticated(OidcLocalAuthenticationResult authenticationResult) {
            return new RefreshResult(Optional.of(authenticationResult), Optional.empty(), Outcome.AUTHENTICATED);
        }

        private static RefreshResult refreshed(OidcLocalAuthenticationResult authenticationResult,
                                               OidcCookieStateHandler.PreparedCookies preparedSession) {
            return new RefreshResult(Optional.of(authenticationResult), Optional.of(preparedSession), Outcome.REFRESHED);
        }

        private static RefreshResult removeLocalAuthentication() {
            return new RefreshResult(Optional.empty(), Optional.empty(), Outcome.REMOVE_COOKIE);
        }

        private static RefreshResult serviceUnavailable() {
            return new RefreshResult(Optional.empty(), Optional.empty(), Outcome.UNAVAILABLE);
        }

        private static RefreshResult unavailableAfterRefresh() {
            return new RefreshResult(Optional.empty(), Optional.empty(), Outcome.UNAVAILABLE_REMOVE_COOKIE);
        }

        private boolean authenticationActiveAt(Instant now) {
            return authenticationResult
                    .map(result -> now.isBefore(result.expiresAt())
                            && result.accessTokenExpiresAt()
                                    .map(expiresAt -> now.isBefore(expiresAt))
                                    .orElse(true))
                    .orElse(true);
        }

        private enum Outcome {
            AUTHENTICATED,
            REFRESHED,
            REMOVE_COOKIE,
            UNAVAILABLE,
            UNAVAILABLE_REMOVE_COOKIE
        }
    }
}
