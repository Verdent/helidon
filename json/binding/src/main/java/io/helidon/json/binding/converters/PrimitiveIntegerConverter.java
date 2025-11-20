package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class PrimitiveIntegerConverter implements JsonConverter<Integer> {

    private static final GenericType<Integer> TYPE = GenericType.create(int.class);

    @Override
    public GenericType<Integer> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, Integer instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public Integer deserialize(JsonParser parser) {
        byte lastByte = parser.currentByte();
        if (lastByte == '\"') {
            parser.nextToken();
            int value = parser.readAsInt();
            lastByte = parser.nextToken();
            if (lastByte != '\"') {
                throw new JsonException("Expected end of the integer value was '\"' but got '" + (char) lastByte + "'");
            }
            return value;
        }
        return parser.readAsInt();
    }

    @Override
    public Integer deserializeNull() {
        return 0;
    }
}
