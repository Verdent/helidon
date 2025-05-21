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
final class PrimitiveLongConverter implements TypedJsonConverter<Long> {

    private static final GenericType<Long> TYPE = GenericType.create(long.class);

    @Override
    public GenericType<Long> type() {
        return TYPE;
    }

    @Override
    public void toJson(Generator generator, Long instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public Long fromJsonValue(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte == '\"') {
            parser.readNextByte();
            long value = parser.readLong();
            lastByte = parser.lastByte();
            if (lastByte != '\"') {
                throw new JsonException("Expected end of the long value was '\"' but got '" + (char) lastByte + "'");
            }
            return value;
        }
        return parser.readLong();
    }

    @Override
    public Long fromNull() {
        return 0L;
    }
}
