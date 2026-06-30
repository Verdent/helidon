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

final class OidcLocalAuthenticationResult {
    private final OidcLocalAuthenticationState state;

    private OidcLocalAuthenticationResult(OidcLocalAuthenticationState state) {
        this.state = Objects.requireNonNull(state);
    }

    static OidcLocalAuthenticationResult fromTokenResponse(String tenantId,
                                                           OidcTokenResponse tokenResponse,
                                                           OidcValidatedIdToken idToken,
                                                           List<String> requestedScopes,
                                                           Optional<JsonObject> userInfo,
                                                           Instant createdAt,
                                                           Duration maxLifetime) {
        Instant idTokenExpiresAt = idToken.jwt().expirationTime().orElseThrow();
        Instant maxExpiresAt = createdAt.plus(maxLifetime);
        Instant expiresAt = idTokenExpiresAt.isBefore(maxExpiresAt) ? idTokenExpiresAt : maxExpiresAt;
        OidcLocalAuthenticationState state = OidcLocalAuthenticationState.builder()
                .tenantId(tenantId)
                .idToken(idToken)
                .accessToken(tokenResponse.accessToken())
                .tokenType(tokenResponse.tokenType())
                .refreshToken(tokenResponse.refreshToken())
                .scope(tokenResponse.scope().or(() -> requestedScope(requestedScopes)))
                .userInfo(userInfo)
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .accessTokenExpiresAt(tokenResponse.expiresIn().map(createdAt::plusSeconds))
                .buildPrototype();
        return fromStoredValues(state);
    }

    static OidcLocalAuthenticationResult fromStoredValues(OidcLocalAuthenticationState state) {
        return new OidcLocalAuthenticationResult(state);
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
