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

import io.helidon.json.JsonObject;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;

final class OidcLocalAuthenticationResult {
    private final OidcLocalAuthenticationState state;

    private OidcLocalAuthenticationResult(OidcLocalAuthenticationState state) {
        this.state = Objects.requireNonNull(state);
    }

    static OidcLocalAuthenticationResult fromTokenResponse(OidcAuthenticationRequestState request,
                                                           OidcTokenResponse tokenResponse,
                                                           OidcValidatedIdToken idToken,
                                                           Optional<JsonObject> userInfo,
                                                           Instant tokenRequestedAt,
                                                           Instant createdAt,
                                                           Duration maxLifetime) {
        Instant idTokenExpiresAt = idToken.jwt().expirationTime().orElseThrow();
        // Add the configured lifetime only when it is bounded by the representable ID Token expiry.
        Instant expiresAt = Duration.between(createdAt, idTokenExpiresAt).compareTo(maxLifetime) > 0
                ? createdAt.plus(maxLifetime)
                : idTokenExpiresAt;
        Optional<Instant> accessTokenExpiresAt = tokenResponse.expiresIn()
                .map(seconds -> OidcTokenLifetime.expiresAt(tokenRequestedAt, seconds));
        OidcLocalAuthenticationState state = OidcLocalAuthenticationState.builder()
                .tenantId(request.tenantId())
                .idToken(idToken)
                .accessToken(tokenResponse.accessToken())
                .tokenType(tokenResponse.tokenType())
                .refreshToken(tokenResponse.refreshToken())
                .browserSessionGeneration(request.browserSessionGeneration())
                .scope(tokenResponse.scope().or(() -> requestedScope(request.requestedScopes())))
                .userInfo(userInfo)
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .accessTokenExpiresAt(accessTokenExpiresAt)
                .buildPrototype();
        return fromStoredValues(state);
    }

    static OidcLocalAuthenticationResult fromStoredValues(OidcLocalAuthenticationState state) {
        return new OidcLocalAuthenticationResult(state);
    }

    OidcLocalAuthenticationResult withBackChannelSession(OidcBackChannelLogoutStore.Session session) {
        return fromStoredValues(OidcLocalAuthenticationState.builder(state)
                                        .backChannelSession(session)
                                        .buildPrototype());
    }

    String tenantId() {
        return state.tenantId();
    }

    OidcValidatedIdToken idToken() {
        return state.idToken();
    }

    String accessToken() {
        return state.accessToken();
    }

    String tokenType() {
        return state.tokenType();
    }

    Optional<String> refreshToken() {
        return state.refreshToken();
    }

    Optional<String> browserSessionGeneration() {
        return state.browserSessionGeneration();
    }

    Optional<String> scope() {
        return state.scope();
    }

    Optional<JsonObject> userInfo() {
        return state.userInfo();
    }

    Instant createdAt() {
        return state.createdAt();
    }

    Instant expiresAt() {
        return state.expiresAt();
    }

    Optional<Instant> accessTokenExpiresAt() {
        return state.accessTokenExpiresAt();
    }

    Optional<OidcBackChannelLogoutStore.Session> backChannelSession() {
        return state.backChannelSession();
    }

    private static Optional<String> requestedScope(List<String> requestedScopes) {
        /*
         * Spec: RFC 6749, 5.1 Successful Response
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
         * Quote: "`scope` OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The scope
         * of the access token as described by Section 3.3."
         */
        String scope = OidcScopeSupport.serializeScopes(requestedScopes);
        if (scope.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(scope);
    }
}
