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

import java.math.BigDecimal;
import java.util.List;

import io.helidon.json.JsonArray;
import io.helidon.json.JsonBoolean;
import io.helidon.json.JsonNull;
import io.helidon.json.JsonNumber;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonString;
import io.helidon.json.JsonValue;

final class TestOidcJsonSupport {
    private TestOidcJsonSupport() {
    }

    static JsonValue jsonValue(Object value) {
        if (value instanceof JsonValue jsonValue) {
            return jsonValue;
        }
        if (value instanceof String string) {
            return JsonString.create(string);
        }
        if (value instanceof Boolean bool) {
            return JsonBoolean.create(bool);
        }
        if (value instanceof Integer number) {
            return JsonNumber.create(BigDecimal.valueOf(number));
        }
        if (value instanceof Long number) {
            return JsonNumber.create(BigDecimal.valueOf(number));
        }
        if (value instanceof BigDecimal number) {
            return JsonNumber.create(number);
        }
        if (value instanceof List<?> list) {
            return JsonArray.create(list.stream()
                                            .map(TestOidcJsonSupport::jsonValue)
                                            .toList());
        }
        if (value == null) {
            return JsonNull.instance();
        }
        throw new IllegalArgumentException("Unsupported JSON claim value type: " + value.getClass().getName());
    }

    static void set(JsonObject.Builder builder, String name, JsonValue value) {
        builder.set(name, value);
    }
}
