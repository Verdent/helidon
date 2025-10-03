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
class PrimitiveIntegerConverter implements TypedJsonConverter<Integer> {

    private static final GenericType<Integer> TYPE = GenericType.create(int.class);

    @Override
    public GenericType<Integer> type() {
        return TYPE;
    }

    @Override
    public void toJson(Generator generator, Integer instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public Integer fromJsonValue(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte == '\"') {
            parser.readNextByte();
            int value = parser.readInt();
            lastByte = parser.nextToken();
            if (lastByte != '\"') {
                throw new JsonException("Expected end of the integer value was '\"' but got '" + (char) lastByte + "'");
            }
            return value;
        }
        return parser.readInt();
    }

    @Override
    public Integer fromNull() {
        return 0;
    }
}
