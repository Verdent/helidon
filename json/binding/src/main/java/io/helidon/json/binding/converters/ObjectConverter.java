package io.helidon.json.binding.converters;

import java.util.Map;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonBinding;
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

    private static final GenericType<Object> TYPE = GenericType.OBJECT;
    private JsonBinding jsonBinding;

    @Override
    public void configure(JsonBinding jsonBinding) {
        this.jsonBinding = jsonBinding;
    }

    @Override
    public GenericType<Object> type() {
        return TYPE;
    }

    @Override
    public Object fromJson(JsonParser parser) {
        throw new JsonException("Deserialization into the Object is not supported.");
    }

    @Override
    public void toJson(Generator generator, Object instance) {
        JsonSerializer<Object> serializer = jsonBinding.getSerializer(instance.getClass());
        serializer.toJson(generator, instance);
    }

}
