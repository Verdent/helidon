package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class ShortConverter implements TypedJsonConverter<Short> {

    @Override
    public void toJson(Generator generator, Short instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public Short fromJsonValue(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte == '\"') {
            parser.readNextByte();
            short value = parser.readAsShort();
            lastByte = parser.nextToken();
            if (lastByte != '\"') {
                throw new JsonException("Expected end of the short value was '\"' but got '" + (char) lastByte + "'");
            }
            return value;
        }
        return parser.readAsShort();
    }

    @Override
    public GenericType<Short> type() {
        return new GenericType<>() {};
    }
}
