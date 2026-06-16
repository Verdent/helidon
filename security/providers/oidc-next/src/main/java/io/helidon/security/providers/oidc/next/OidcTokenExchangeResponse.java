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

final class OidcTokenExchangeResponse {
    static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    static final String BEARER_TOKEN_TYPE = "Bearer";

    private final String accessToken;
    private final String issuedTokenType;
    private final String tokenType;
    private final Long expiresIn;
    private final String scope;

    private OidcTokenExchangeResponse(String accessToken,
                                      String issuedTokenType,
                                      String tokenType,
                                      Long expiresIn,
                                      String scope) {
        this.accessToken = accessToken;
        this.issuedTokenType = issuedTokenType;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.scope = scope;
    }

    static OidcTokenExchangeResponse fromJson(JsonObject json) {
        /*
         * Spec: RFC 8693, 2.2.1 Successful Response
         * https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2.1
         * Quote: "`access_token` REQUIRED. The security token issued by the authorization server in response to the
         * token exchange request."
         * Quote: "`issued_token_type` REQUIRED. An identifier, as described in Section 3, for the representation of the
         * issued security token."
         * Quote: "`token_type` REQUIRED. A case-insensitive value specifying the method of using the access token"
         */
        String accessToken = requiredString(json, "access_token");
        String issuedTokenType = requiredString(json, "issued_token_type");
        String tokenType = requiredString(json, "token_type");
        if (!ACCESS_TOKEN_TYPE.equals(issuedTokenType)) {
            throw new IllegalArgumentException("Token Exchange response issued_token_type is not supported");
        }
        if (!"bearer".equalsIgnoreCase(tokenType)) {
            throw new IllegalArgumentException("Token Exchange response token_type is not supported");
        }
        return new OidcTokenExchangeResponse(accessToken,
                                             issuedTokenType,
                                             tokenType,
                                             expiresIn(json).orElse(null),
                                             stringValue(json, "scope")
                                                     .map(scope -> OidcScopeSupport.validateScopeString(
                                                             scope,
                                                             "Token Exchange response field scope"))
                                                     .orElse(null));
    }

    String accessToken() {
        return accessToken;
    }

    String issuedTokenType() {
        return issuedTokenType;
    }

    String tokenType() {
        return tokenType;
    }

    Optional<Long> expiresIn() {
        return Optional.ofNullable(expiresIn);
    }

    Optional<String> scope() {
        return Optional.ofNullable(scope);
    }

    private static String requiredString(JsonObject json, String name) {
        return stringValue(json, name)
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new IllegalArgumentException("Token Exchange response is invalid"));
    }

    private static Optional<String> stringValue(JsonObject json, String name) {
        return json.value(name)
                .map(jsonValue -> {
                    if (jsonValue.type() == JsonValueType.STRING) {
                        return jsonValue.asString().value();
                    }
                    throw new IllegalArgumentException("Token Exchange response field " + name + " must be a string");
                });
    }

    private static Optional<Long> expiresIn(JsonObject json) {
        return json.numberValue("expires_in")
                .map(BigDecimal::longValueExact)
                .map(value -> {
                    if (value < 0) {
                        throw new IllegalArgumentException("Token Exchange response expires_in must not be negative");
                    }
                    return value;
                });
    }
}
