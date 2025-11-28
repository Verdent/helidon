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
class IntegerConverter implements JsonConverter<Integer> {

    @Override
    public void serialize(Generator generator, Integer instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(Integer instance) {
        return instance.toString();
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
    public GenericType<Integer> type() {
        return GenericType.create(Integer.class);
    }
}
