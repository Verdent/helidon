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
class PrimitiveDoubleConverter implements JsonConverter<Double> {

    private static final GenericType<Double> TYPE = GenericType.create(double.class);

    @Override
    public GenericType<Double> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, Double instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public Double deserialize(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte == '\"') {
            parser.readNextByte();
            double value = parser.readAsDouble();
            lastByte = parser.nextToken();
            if (lastByte != '\"') {
                throw new JsonException("Expected end of the double value was '\"' but got '" + (char) lastByte + "'");
            }
            return value;
        }
        return parser.readAsDouble();
    }

    @Override
    public Double deserializeNull() {
        return 0.0;
    }
}
