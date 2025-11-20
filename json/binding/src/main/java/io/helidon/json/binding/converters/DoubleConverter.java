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
class DoubleConverter implements JsonConverter<Double> {

    private static final GenericType<Double> TYPE = GenericType.create(Double.class);

    @Override
    public GenericType<Double> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, Double instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(Double instance) {
        return instance.toString();
    }

    @Override
    public Double deserialize(JsonParser parser) {
        byte lastByte = parser.currentByte();
        if (lastByte == '\"') {
            parser.nextToken();
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
