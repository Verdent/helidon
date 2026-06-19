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
import java.util.Objects;
import java.util.Optional;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonValueType;

final class OidcTokenResponse {
    private final String accessToken;
    private final String tokenType;
    private final Optional<String> idToken;
    private final Optional<String> refreshToken;
    private final Optional<Long> expiresIn;
    private final Optional<String> scope;

    private OidcTokenResponse(String accessToken,
                              String tokenType,
                              Optional<String> idToken,
                              Optional<String> refreshToken,
                              Optional<Long> expiresIn,
                              Optional<String> scope) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.idToken = Objects.requireNonNull(idToken);
        this.refreshToken = Objects.requireNonNull(refreshToken);
        this.expiresIn = Objects.requireNonNull(expiresIn);
        this.scope = Objects.requireNonNull(scope);
    }

    static OidcTokenResponse fromAuthorizationCodeJson(JsonObject json) {
        /*
         * Spec: OpenID Connect Core 1.0, 3.1.3.3 Successful Token Response
         * https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
         * Quote: "The OAuth 2.0 `token_type` response parameter value MUST be `Bearer`, as specified in OAuth 2.0
         * Bearer Token Usage, unless another Token Type has been negotiated with the Client."
         * Quote: "In addition to the response parameters specified by OAuth 2.0, the following parameters MUST be
         * included in the response: `id_token` ID Token value associated with the authenticated session."
         */
        return create(json, true);
    }

    static OidcTokenResponse fromRefreshJson(JsonObject json) {
        /*
         * Spec: OpenID Connect Core 1.0, 12.2 Successful Refresh Response
         * https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
         * Quote: "Upon successful validation of the Refresh Token, the response body is the Token Response of Section
         * 3.1.3.3 (Successful Token Response) except that it might not contain an `id_token`."
         */
        return create(json, false);
    }

    static OidcTokenResponse fromClientCredentialsJson(JsonObject json) {
        /*
         * Spec: RFC 6749, 4.4.3 Access Token Response
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.3
         * Quote: "If the access token request is valid and authorized, the authorization server issues an access token
         * as described in Section 5.1."
         * Quote: "A refresh token SHOULD NOT be included."
         */
        return create(json, false);
    }

    private static OidcTokenResponse create(JsonObject json, boolean requireIdToken) {
        String accessToken = requiredString(json, "access_token");
        String tokenType = requiredString(json, "token_type");
        Optional<String> idToken = requireIdToken
                ? Optional.of(requiredString(json, "id_token"))
                : stringValue(json, "id_token");
        if (!"bearer".equalsIgnoreCase(tokenType)) {
            throw new IllegalArgumentException("Token Endpoint response token_type is not supported");
        }
        return new OidcTokenResponse(accessToken,
                                     tokenType,
                                     idToken,
                                     stringValue(json, "refresh_token"),
                                     expiresIn(json),
                                     stringValue(json, "scope")
                                             .map(scope -> OidcScopeSupport.validateScopeString(
                                                     scope,
                                                     "Token Endpoint response field scope")));
    }

    String accessToken() {
        return accessToken;
    }

    String tokenType() {
        return tokenType;
    }

    Optional<String> idToken() {
        return idToken;
    }

    Optional<String> refreshToken() {
        return refreshToken;
    }

    Optional<Long> expiresIn() {
        return expiresIn;
    }

    Optional<String> scope() {
        return scope;
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
