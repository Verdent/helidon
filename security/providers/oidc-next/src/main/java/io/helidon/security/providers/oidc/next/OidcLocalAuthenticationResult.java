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
    private final String tenantId;
    private final OidcValidatedIdToken idToken;
    private final String accessToken;
    private final String tokenType;
    private final Optional<String> refreshToken;
    private final Optional<String> scope;
    private final Optional<JsonObject> userInfo;
    private final Instant createdAt;
    private final Instant expiresAt;
    private final Optional<Instant> accessTokenExpiresAt;

    private OidcLocalAuthenticationResult(String tenantId,
                                          OidcValidatedIdToken idToken,
                                          String accessToken,
                                          String tokenType,
                                          Optional<String> refreshToken,
                                          Optional<String> scope,
                                          Optional<JsonObject> userInfo,
                                          Instant createdAt,
                                          Instant expiresAt,
                                          Optional<Instant> accessTokenExpiresAt) {
        this.tenantId = tenantId;
        this.idToken = idToken;
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.refreshToken = Objects.requireNonNull(refreshToken);
        this.scope = Objects.requireNonNull(scope);
        this.userInfo = Objects.requireNonNull(userInfo);
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.accessTokenExpiresAt = Objects.requireNonNull(accessTokenExpiresAt);
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
        return new OidcLocalAuthenticationResult(tenantId,
                                                 idToken,
                                                 tokenResponse.accessToken(),
                                                 tokenResponse.tokenType(),
                                                 tokenResponse.refreshToken(),
                                                 tokenResponse.scope().or(() -> requestedScope(requestedScopes)),
                                                 userInfo,
                                                 createdAt,
                                                 expiresAt,
                                                 tokenResponse.expiresIn().map(createdAt::plusSeconds));
    }

    static OidcLocalAuthenticationResult fromStoredValues(String tenantId,
                                                          OidcValidatedIdToken idToken,
                                                          String accessToken,
                                                          String tokenType,
                                                          Optional<String> refreshToken,
                                                          Optional<String> scope,
                                                          Optional<JsonObject> userInfo,
                                                          Instant createdAt,
                                                          Instant expiresAt,
                                                          Optional<Instant> accessTokenExpiresAt) {
        return new OidcLocalAuthenticationResult(tenantId,
                                                 idToken,
                                                 accessToken,
                                                 tokenType,
                                                 refreshToken,
                                                 scope,
                                                 userInfo,
                                                 createdAt,
                                                 expiresAt,
                                                 accessTokenExpiresAt);
    }

    String tenantId() {
        return tenantId;
    }

    OidcValidatedIdToken idToken() {
        return idToken;
    }

    String accessToken() {
        return accessToken;
    }

    String tokenType() {
        return tokenType;
    }

    Optional<String> refreshToken() {
        return refreshToken;
    }

    Optional<String> scope() {
        return scope;
    }

    Optional<JsonObject> userInfo() {
        return userInfo;
    }

    Instant createdAt() {
        return createdAt;
    }

    Instant expiresAt() {
        return expiresAt;
    }

    Optional<Instant> accessTokenExpiresAt() {
        return accessTokenExpiresAt;
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
