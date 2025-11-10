package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonBindingConfigurator;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.PerLookup
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class ObjectConverter implements TypedJsonConverter<Object> {

    private JsonBindingConfigurator jsonBindingConfigurator;

    @Override
    public void configure(JsonBindingConfigurator jsonBindingConfigurator) {
        this.jsonBindingConfigurator = jsonBindingConfigurator;
    }

    @Override
    public GenericType<Object> type() {
        return GenericType.OBJECT;
    }

    @Override
    public Object deserialize(JsonParser parser) {
        throw new JsonException("Deserialization into the Object is not supported.");
    }

    @Override
    @SuppressWarnings("unchecked")
    public void serialize(Generator generator, Object instance, boolean writeNulls) {
        JsonSerializer<Object> serializer = (JsonSerializer<Object>) jsonBindingConfigurator.getSerializer(instance.getClass());
        serializer.serialize(generator, instance, writeNulls);
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    @SuppressWarnings("unchecked")
    public String serializeAsMapKey(Object instance) {
        JsonSerializer<Object> serializer = (JsonSerializer<Object>) jsonBindingConfigurator.getSerializer(instance.getClass());
        return serializer.serializeAsMapKey(instance);
    }
}
