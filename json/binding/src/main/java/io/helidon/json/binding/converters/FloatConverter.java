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
class FloatConverter implements TypedJsonConverter<Float> {

    private static final GenericType<Float> TYPE = GenericType.create(Float.class);

    @Override
    public GenericType<Float> type() {
        return TYPE;
    }

    @Override
    public void toJson(Generator generator, Float instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public Float fromJsonValue(JsonParser parser) {
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

}
