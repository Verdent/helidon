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
class PrimitiveByteConverter implements TypedJsonConverter<Byte> {

    private static final GenericType<Byte> TYPE = GenericType.create(byte.class);

    @Override
    public GenericType<Byte> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, Byte instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public Byte deserialize(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte == '\"') {
            parser.readNextByte();
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
    public Byte deserializeNull() {
        return 0;
    }
}
