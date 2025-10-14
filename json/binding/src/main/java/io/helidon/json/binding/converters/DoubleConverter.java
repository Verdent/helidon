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
class DoubleConverter implements TypedJsonConverter<Double> {

    private static final GenericType<Double> TYPE = GenericType.create(Double.class);

    @Override
    public GenericType<Double> type() {
        return TYPE;
    }

    @Override
    public void toJson(Generator generator, Double instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public Double fromJsonValue(JsonParser parser) {
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

}
