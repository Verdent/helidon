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

package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonException;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class PrimitiveBooleanConverter implements JsonConverter<Boolean> {

    private static final GenericType<Boolean> TYPE = GenericType.create(boolean.class);

    @Override
    public GenericType<Boolean> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, Boolean instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public Boolean deserialize(JsonParser parser) {
        byte lastByte = parser.currentByte();
        switch (lastByte) {
        case '\"':
            lastByte = parser.nextToken();
            boolean toReturn;
            switch (lastByte) {
            case 't':
            case 'f':
                toReturn = parser.readAsBoolean();
                break;
            case 'n':
                parser.checkNull();
                toReturn = false;
                break;
            default:
                throw new JsonException("Expected Boolean value but got '" + (char) lastByte + "'");
            }
            if (parser.nextToken() != '\"') {
                throw new JsonException("Expected end of the boolean value was '\"' but got '" + (char) lastByte + "'");
            }
            return toReturn;
        case 't':
        case 'f':
            return parser.readAsBoolean();
        default:
            throw new JsonException("Expected Boolean value but got '" + (char) lastByte + "'");
        }
    }

    @Override
    public Boolean deserializeNull() {
        return false;
    }
}
