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
class PrimitiveLongConverter implements TypedJsonConverter<Long> {

    private static final GenericType<Long> TYPE = GenericType.create(long.class);

    @Override
    public GenericType<Long> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, Long instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public Long deserialize(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte == '\"') {
            parser.readNextByte();
            long value = parser.readAsLong();
            lastByte = parser.nextToken();
            if (lastByte != '\"') {
                throw new JsonException("Expected end of the long value was '\"' but got '" + (char) lastByte + "'");
            }
            return value;
        }
        return parser.readAsLong();
    }

    @Override
    public Long deserializeNull() {
        return 0L;
    }
}
