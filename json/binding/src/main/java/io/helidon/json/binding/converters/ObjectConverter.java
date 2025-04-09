package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonBindingConfigurer;
import io.helidon.json.binding.JsonConfigurable;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
final class ObjectConverter implements TypedJsonConverter<Object>, JsonConfigurable {

    private JsonBindingConfigurer jsonBindingConfigurer;

    @Override
    public void configure(JsonBindingConfigurer jsonBindingConfigurer) {
        this.jsonBindingConfigurer = jsonBindingConfigurer;
    }

    @Override
    public GenericType<Object> type() {
        return GenericType.OBJECT;
    }

    @Override
    public Object fromJsonValue(JsonParser parser) {
        throw new JsonException("Deserialization into the Object is not supported.");
    }

    @Override
    @SuppressWarnings("unchecked")
    public void toJson(Generator generator, Object instance, boolean writeNulls) {
        JsonSerializer<Object> serializer = (JsonSerializer<Object>) jsonBindingConfigurer.getSerializer(instance.getClass());
        serializer.toJson(generator, instance, writeNulls);
    }

}
