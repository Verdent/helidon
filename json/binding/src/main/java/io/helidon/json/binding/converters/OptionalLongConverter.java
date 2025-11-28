package io.helidon.json.binding.converters;

import java.util.OptionalLong;

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
class OptionalLongConverter implements JsonConverter<OptionalLong> {

    private static final GenericType<OptionalLong> TYPE = GenericType.create(OptionalLong.class);

    private JsonDeserializer<Long> deserializer;
    private JsonSerializer<Long> serializer;

    @Override
    public void serialize(Generator generator, OptionalLong instance, boolean writeNulls) {
        if (instance.isEmpty()) {
            generator.writeNull();
            return;
        }
        serializer.serialize(generator, instance.getAsLong(), writeNulls);
    }

    @Override
    public OptionalLong deserialize(JsonParser parser) {
        return OptionalLong.of(deserializer.deserialize(parser));
    }

    @Override
    public OptionalLong deserializeNull() {
        return OptionalLong.empty();
    }

    @Override
    public void configure(JsonBindingConfigurator jsonBindingConfigurator) {
        deserializer = jsonBindingConfigurator.deserializer(long.class);
        serializer = jsonBindingConfigurator.serializer(long.class);
    }

    @Override
    public GenericType<OptionalLong> type() {
        return TYPE;
    }
}
