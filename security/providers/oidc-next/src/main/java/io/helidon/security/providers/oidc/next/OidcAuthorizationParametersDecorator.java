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

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.helidon.builder.api.Prototype;
import io.helidon.json.JsonArray;
import io.helidon.json.JsonNumber;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonString;
import io.helidon.json.JsonValue;

final class OidcAuthorizationParametersDecorator
        implements Prototype.BuilderDecorator<OidcAuthorizationParameters.BuilderBase<?, ?>> {
    private static final Set<String> STRING_PARAMETERS = Set.of("response_type", "client_id", "redirect_uri", "scope",
            "state", "nonce", "prompt", "display", "ui_locales", "claims_locales", "login_hint", "id_token_hint",
            "acr_values", "response_mode", "code_challenge", "code_challenge_method");
    private static final Set<String> RESERVED_PARAMETERS = Set.of("request", "request_uri", "iss", "aud", "iat", "exp",
                                                                 "nbf", "jti");

    @Override
    public void decorate(OidcAuthorizationParameters.BuilderBase<?, ?> builder) {
        Map<String, List<JsonValue>> snapshot = new LinkedHashMap<>();
        for (Map.Entry<String, List<JsonValue>> entry : builder.parameters().entrySet()) {
            String name = entry.getKey();
            if (name.isEmpty() || name.codePoints().anyMatch(c -> Character.isWhitespace(c) || Character.isISOControl(c))) {
                throw new IllegalArgumentException("Authorization parameter name must not be empty "
                                                   + "or contain whitespace/control");
            }
            if (RESERVED_PARAMETERS.contains(name)) {
                throw new IllegalArgumentException("Authorization parameter is reserved: " + name);
            }
            List<JsonValue> values = List.copyOf(entry.getValue());
            if (values.isEmpty()) {
                throw new IllegalArgumentException("Authorization parameter must have an occurrence: " + name);
            }
            if (STRING_PARAMETERS.contains(name)
                    && (values.size() != 1 || !(values.getFirst() instanceof JsonString))) {
                throw new IllegalArgumentException("Authorization parameter must be one string: " + name);
            }
            switch (name) {
            case "max_age" -> {
                if (values.size() != 1 || !(values.getFirst() instanceof JsonNumber age)) {
                    throw new IllegalArgumentException("max_age must be one non-negative whole-second number");
                }
                try {
                    long seconds = age.bigDecimalValue().longValueExact();
                    if (seconds < 0) {
                        throw new IllegalArgumentException("max_age must be non-negative");
                    }
                    values = List.of(JsonNumber.create(seconds));
                } catch (ArithmeticException e) {
                    throw new IllegalArgumentException("max_age must be whole seconds within the long range", e);
                }
            }
            case "claims" -> {
                if (values.size() != 1 || !(values.getFirst() instanceof JsonObject)) {
                    throw new IllegalArgumentException("claims must be one JSON object");
                }
            }
            case "authorization_details" -> {
                if (values.size() != 1 || !(values.getFirst() instanceof JsonArray details)) {
                    throw new IllegalArgumentException("authorization_details must be one JSON array");
                }
                for (JsonValue detail : details.values()) {
                    if (!(detail instanceof JsonObject object)
                            || object.value("type")
                                    .filter(value -> value instanceof JsonString type && !type.value().isBlank()).isEmpty()) {
                        throw new IllegalArgumentException("authorization_details entries must be objects with a type string");
                    }
                }
            }
            case "resource" -> {
                for (JsonValue value : values) {
                    if (!(value instanceof JsonString resource)) {
                        throw new IllegalArgumentException("resource occurrences must be strings");
                    }
                    URI uri = URI.create(resource.value());
                    if (!uri.isAbsolute() || uri.getRawFragment() != null) {
                        throw new IllegalArgumentException("resource must be an absolute URI without a fragment");
                    }
                }
            }
            case "registration" -> throw new IllegalArgumentException("Self-Issued OP registration requests are unsupported");
            default -> {
                // Other extension parameters retain their explicitly supplied JSON types and occurrence counts.
            }
            }
            snapshot.put(name, values);
        }
        builder.parameters(snapshot);
    }
}
