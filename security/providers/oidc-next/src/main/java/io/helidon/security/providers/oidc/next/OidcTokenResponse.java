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

import java.math.BigDecimal;
import java.util.Optional;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonValueType;

final class OidcTokenResponse {
    private final String accessToken;
    private final String tokenType;
    private final String idToken;
    private final String refreshToken;
    private final Long expiresIn;
    private final String scope;
    private final JsonObject rawResponse;

    private OidcTokenResponse(String accessToken,
                              String tokenType,
                              String idToken,
                              String refreshToken,
                              Long expiresIn,
                              String scope,
                              JsonObject rawResponse) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.scope = scope;
        this.rawResponse = rawResponse;
    }

    static OidcTokenResponse fromJson(JsonObject json) {
        /*
         * Spec: OpenID Connect Core 1.0, 3.1.3.3 Successful Token Response
         * https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
         * Quotes: "`access_token` OAuth 2.0 Access Token"; "`token_type` OAuth 2.0 Token Type";
         * "`id_token` ID Token value associated with the authenticated session".
         */
        String accessToken = requiredString(json, "access_token");
        String tokenType = requiredString(json, "token_type");
        String idToken = requiredString(json, "id_token");
        if (!"bearer".equalsIgnoreCase(tokenType)) {
            throw new IllegalArgumentException("Token Endpoint response token_type is not supported");
        }
        return new OidcTokenResponse(accessToken,
                                     tokenType,
                                     idToken,
                                     stringValue(json, "refresh_token").orElse(null),
                                     expiresIn(json).orElse(null),
                                     stringValue(json, "scope").orElse(null),
                                     json);
    }

    String accessToken() {
        return accessToken;
    }

    String tokenType() {
        return tokenType;
    }

    String idToken() {
        return idToken;
    }

    Optional<String> refreshToken() {
        return Optional.ofNullable(refreshToken);
    }

    Optional<Long> expiresIn() {
        return Optional.ofNullable(expiresIn);
    }

    Optional<String> scope() {
        return Optional.ofNullable(scope);
    }

    JsonObject rawResponse() {
        return rawResponse;
    }

    private static String requiredString(JsonObject json, String name) {
        return stringValue(json, name)
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new IllegalArgumentException("Token Endpoint response is invalid"));
    }

    private static Optional<String> stringValue(JsonObject json, String name) {
        return json.value(name)
                .map(jsonValue -> {
                    if (jsonValue.type() == JsonValueType.STRING) {
                        return jsonValue.asString().value();
                    }
                    throw new IllegalArgumentException("Token Endpoint response field " + name + " must be a string");
                });
    }

    private static Optional<Long> expiresIn(JsonObject json) {
        return json.numberValue("expires_in")
                .map(BigDecimal::longValueExact)
                .map(value -> {
                    if (value < 0) {
                        throw new IllegalArgumentException("Token Endpoint response expires_in must not be negative");
                    }
                    return value;
                });
    }
}
