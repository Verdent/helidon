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
class PrimitiveFloatConverter implements TypedJsonConverter<Float> {

    private static final GenericType<Float> TYPE = GenericType.create(float.class);

    @Override
    public GenericType<Float> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, Float instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public Float deserialize(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte == '\"') {
            parser.readNextByte();
            float value = parser.readAsFloat();
            lastByte = parser.nextToken();
            if (lastByte != '\"') {
                throw new JsonException("Expected end of the float value was '\"' but got '" + (char) lastByte + "'");
            }
            return value;
        }
        return parser.readAsFloat();
    }

    @Override
    public Float deserializeNull() {
        return 0.0F;
    }
}
