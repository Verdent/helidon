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
class ShortConverter implements JsonConverter<Short> {

    @Override
    public void serialize(Generator generator, Short instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(Short instance) {
        return instance.toString();
    }

    @Override
    public Short deserialize(JsonParser parser) {
        byte lastByte = parser.currentByte();
        if (lastByte == '\"') {
            parser.nextToken();
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
        return GenericType.create(Short.class);
    }
}
