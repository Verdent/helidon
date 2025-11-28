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
class ByteConverter implements JsonConverter<Byte> {

    @Override
    public void serialize(Generator generator, Byte instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(Byte instance) {
        return instance.toString();
    }

    @Override
    public Byte deserialize(JsonParser parser) {
        byte lastByte = parser.currentByte();
        if (lastByte == '\"') {
            parser.nextToken();
            byte value = parser.readAsByte();
            lastByte = parser.nextToken();
            if (lastByte != '\"') {
                throw new JsonException("Expected end of the byte value was '\"' but got '" + (char) lastByte + "'");
            }
            return value;
        }
        return parser.readAsByte();
    }

    @Override
    public GenericType<Byte> type() {
        return GenericType.create(Byte.class);
    }
}
