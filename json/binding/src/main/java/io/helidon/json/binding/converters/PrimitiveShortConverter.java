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
class PrimitiveShortConverter implements JsonConverter<Short> {

    private static final GenericType<Short> TYPE = GenericType.create(short.class);

    @Override
    public GenericType<Short> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, Short instance, boolean writeNulls) {
        generator.write(instance);
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
    public Short deserializeNull() {
        return 0;
    }
}
