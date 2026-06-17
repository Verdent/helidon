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

import io.helidon.json.JsonObject;
import io.helidon.json.JsonValueType;

final class OidcPushedAuthorizationResponse {
    private final String requestUri;
    private final long expiresIn;

    private OidcPushedAuthorizationResponse(String requestUri, long expiresIn) {
        this.requestUri = requestUri;
        this.expiresIn = expiresIn;
    }

    static OidcPushedAuthorizationResponse fromJson(JsonObject json) {
        /*
         * Spec: RFC 9126, 2.2 Successful Response
         * https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2
         * Quote: "The authorization server MUST provide a `request_uri` in the response."
         * Quote: "The authorization server MUST provide an `expires_in` value."
         */
        String requestUri = json.value("request_uri")
                .map(jsonValue -> {
                    if (jsonValue.type() == JsonValueType.STRING) {
                        return jsonValue.asString().value();
                    }
                    throw new IllegalArgumentException("Pushed Authorization Request response request_uri is invalid");
                })
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new IllegalArgumentException(
                        "Pushed Authorization Request response request_uri is invalid"));
        long expiresIn = json.numberValue("expires_in")
                .map(BigDecimal::longValueExact)
                .filter(value -> value > 0)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Pushed Authorization Request response expires_in is invalid"));
        return new OidcPushedAuthorizationResponse(requestUri, expiresIn);
    }

    String requestUri() {
        return requestUri;
    }

    long expiresIn() {
        return expiresIn;
    }
}
