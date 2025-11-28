package io.helidon.json.binding.converters;

import java.util.OptionalDouble;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonBindingConfigurator;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.Generator;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.PerLookup
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class OptionalDoubleConverter implements JsonConverter<OptionalDouble> {

    private static final GenericType<OptionalDouble> TYPE = GenericType.create(OptionalDouble.class);

    private JsonDeserializer<Double> deserializer;
    private JsonSerializer<Double> serializer;

    @Override
    public void serialize(Generator generator, OptionalDouble instance, boolean writeNulls) {
        if (instance.isEmpty()) {
            generator.writeNull();
            return;
        }
        serializer.serialize(generator, instance.getAsDouble(), writeNulls);
    }

    @Override
    public OptionalDouble deserialize(JsonParser parser) {
        return OptionalDouble.of(deserializer.deserialize(parser));
    }

    @Override
    public OptionalDouble deserializeNull() {
        return OptionalDouble.empty();
    }

    @Override
    public void configure(JsonBindingConfigurator jsonBindingConfigurator) {
        deserializer = jsonBindingConfigurator.deserializer(double.class);
        serializer = jsonBindingConfigurator.serializer(double.class);
    }

    @Override
    public GenericType<OptionalDouble> type() {
        return TYPE;
    }
}
