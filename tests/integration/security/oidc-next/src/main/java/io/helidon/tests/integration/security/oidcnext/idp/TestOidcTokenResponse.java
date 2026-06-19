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

package io.helidon.tests.integration.security.oidcnext.idp;

import java.util.Optional;

import io.helidon.json.JsonObject;

/**
 * Token endpoint response model produced by the test IdP.
 */
public final class TestOidcTokenResponse {
    private final String accessToken;
    private final String tokenType;
    private final String issuedTokenType;
    private final Long expiresIn;
    private final String scope;
    private final String idToken;
    private final String refreshToken;

    TestOidcTokenResponse(String accessToken,
                          String tokenType,
                          String issuedTokenType,
                          Long expiresIn,
                          String scope,
                          String idToken,
                          String refreshToken) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.issuedTokenType = issuedTokenType;
        this.expiresIn = expiresIn;
        this.scope = scope;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
    }

    /**
     * Access token.
     *
     * @return access token
     */
    public String accessToken() {
        return accessToken;
    }

    /**
     * Token type.
     *
     * @return token type
     */
    public String tokenType() {
        return tokenType;
    }

    /**
     * Issued token type.
     *
     * @return issued token type
     */
    public Optional<String> issuedTokenType() {
        return Optional.ofNullable(issuedTokenType);
    }

    /**
     * Expiration in seconds.
     *
     * @return expiration
     */
    public Optional<Long> expiresIn() {
        return Optional.ofNullable(expiresIn);
    }

    /**
     * Issued scope.
     *
     * @return scope
     */
    public Optional<String> scope() {
        return Optional.ofNullable(scope);
    }

    /**
     * ID token.
     *
     * @return ID token
     */
    public Optional<String> idToken() {
        return Optional.ofNullable(idToken);
    }

    /**
     * Refresh token.
     *
     * @return refresh token
     */
    public Optional<String> refreshToken() {
        return Optional.ofNullable(refreshToken);
    }

    /**
     * JSON representation suitable for a token endpoint response body.
     *
     * @return JSON object
     */
    public JsonObject asJson() {
        JsonObject.Builder builder = JsonObject.builder()
                .set("access_token", accessToken)
                .set("token_type", tokenType);
        if (issuedTokenType != null) {
            builder.set("issued_token_type", issuedTokenType);
        }
        if (expiresIn != null) {
            builder.set("expires_in", expiresIn);
        }
        if (scope != null) {
            builder.set("scope", scope);
        }
        if (idToken != null) {
            builder.set("id_token", idToken);
        }
        if (refreshToken != null) {
            builder.set("refresh_token", refreshToken);
        }
        return builder.build();
    }
}
