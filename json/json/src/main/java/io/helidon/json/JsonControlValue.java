/*
 * Copyright (c) 2025 Oracle and/or its affiliates.
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

package io.helidon.json;

final class JsonControlValue extends JsonValue {

    private final byte controlChar;

    JsonControlValue(char controlChar) {
        this.controlChar = (byte) controlChar;
    }

    // Reuse common control tokens to reduce allocations during JsonValueParser traversal
    static final JsonControlValue RBRACE   = new JsonControlValue('}');
    static final JsonControlValue RBRACKET = new JsonControlValue(']');
    static final JsonControlValue COLON    = new JsonControlValue(':');
    static final JsonControlValue COMMA    = new JsonControlValue(',');

    @Override
    public JsonValueType type() {
        return JsonValueType.CONTROL;
    }

    @Override
    public void toJson(Generator generator) {
        throw new UnsupportedOperationException();
    }

    @Override
    byte jsonStartChar() {
        return controlChar;
    }

    @Override
    public String toString() {
        return "" + (char) controlChar;
    }
}
