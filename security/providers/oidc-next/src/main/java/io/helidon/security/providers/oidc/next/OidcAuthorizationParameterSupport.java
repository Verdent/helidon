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

import java.util.List;
import java.util.Map;

import io.helidon.common.parameters.Parameters;
import io.helidon.json.JsonArray;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonString;
import io.helidon.json.JsonValue;

final class OidcAuthorizationParameterSupport {
    private OidcAuthorizationParameterSupport() {
    }

    static String requiredString(OidcAuthorizationParameters parameters, String name) {
        List<JsonValue> values = parameters.parameters().getOrDefault(name, List.of());
        if (values.size() != 1 || !(values.getFirst() instanceof JsonString value)) {
            throw new IllegalStateException("Authorization Request parameter must be one string: " + name);
        }
        return value.value();
    }

    static Parameters form(OidcAuthorizationParameters parameters) {
        Parameters.Builder form = Parameters.builder("oidc-authorization-request");
        for (Map.Entry<String, List<JsonValue>> entry : parameters.parameters().entrySet()) {
            for (JsonValue value : entry.getValue()) {
                form.add(entry.getKey(), value instanceof JsonString string ? string.value() : value.toString());
            }
        }
        return form.build();
    }

    static JsonObject payload(OidcAuthorizationParameters parameters) {
        JsonObject.Builder payload = JsonObject.builder();
        for (Map.Entry<String, List<JsonValue>> entry : parameters.parameters().entrySet()) {
            List<JsonValue> values = entry.getValue();
            payload.set(entry.getKey(), values.size() == 1 ? values.getFirst() : JsonArray.create(values));
        }
        return payload.build();
    }
}
