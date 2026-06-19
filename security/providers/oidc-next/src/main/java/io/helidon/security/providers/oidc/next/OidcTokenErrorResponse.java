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

import java.util.Objects;
import java.util.Optional;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonValueType;

final class OidcTokenErrorResponse {
    private final String error;
    private final Optional<String> errorDescription;
    private final Optional<String> errorUri;

    private OidcTokenErrorResponse(String error, Optional<String> errorDescription, Optional<String> errorUri) {
        this.error = error;
        this.errorDescription = Objects.requireNonNull(errorDescription);
        this.errorUri = Objects.requireNonNull(errorUri);
    }

    static OidcTokenErrorResponse fromJson(JsonObject json) {
        /*
         * Spec: RFC 6749, 5.2 Error Response
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
         * Quote: "`error` REQUIRED. A single ASCII error code."
         */
        String error = stringValue(json, "error")
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new IllegalArgumentException("Token Endpoint Error Response is invalid"));
        if (!OidcOAuthErrorFields.validError(error)) {
            throw new IllegalArgumentException("Token Endpoint Error Response is invalid");
        }
        Optional<String> errorDescription = stringValue(json, "error_description");
        if (errorDescription.filter(description -> !OidcOAuthErrorFields.validErrorDescription(description)).isPresent()) {
            throw new IllegalArgumentException("Token Endpoint Error Response is invalid");
        }
        Optional<String> errorUri = stringValue(json, "error_uri");
        if (errorUri.filter(uri -> !OidcOAuthErrorFields.validErrorUri(uri)).isPresent()) {
            throw new IllegalArgumentException("Token Endpoint Error Response is invalid");
        }
        return new OidcTokenErrorResponse(error,
                                          errorDescription,
                                          errorUri);
    }

    String error() {
        return error;
    }

    Optional<String> errorDescription() {
        return errorDescription;
    }

    Optional<String> errorUri() {
        return errorUri;
    }

    private static Optional<String> stringValue(JsonObject json, String name) {
        return json.value(name)
                .map(jsonValue -> {
                    if (jsonValue.type() == JsonValueType.STRING) {
                        return jsonValue.asString().value();
                    }
                    throw new IllegalArgumentException("Token Endpoint Error Response field " + name
                                                               + " must be a string");
                });
    }
}
