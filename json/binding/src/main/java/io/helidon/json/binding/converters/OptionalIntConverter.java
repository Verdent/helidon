package io.helidon.json.binding.converters;

import java.util.OptionalInt;

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
class OptionalIntConverter implements JsonConverter<OptionalInt> {

    private static final GenericType<OptionalInt> TYPE = GenericType.create(OptionalInt.class);

    private JsonDeserializer<Integer> deserializer;
    private JsonSerializer<Integer> serializer;

    @Override
    public void serialize(Generator generator, OptionalInt instance, boolean writeNulls) {
        if (instance.isEmpty()) {
            generator.writeNull();
            return;
        }
        serializer.serialize(generator, instance.getAsInt(), writeNulls);
    }

    @Override
    public OptionalInt deserialize(JsonParser parser) {
        return OptionalInt.of(deserializer.deserialize(parser));
    }

    @Override
    public OptionalInt deserializeNull() {
        return OptionalInt.empty();
    }

    @Override
    public void configure(JsonBindingConfigurator jsonBindingConfigurator) {
        deserializer = jsonBindingConfigurator.getDeserializer(int.class);
        serializer = jsonBindingConfigurator.getSerializer(int.class);
    }

    @Override
    public GenericType<OptionalInt> type() {
        return TYPE;
    }
}
