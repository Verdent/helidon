package io.helidon.json.binding;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import io.helidon.builder.api.RuntimeType;
import io.helidon.common.GenericType;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

@RuntimeType.PrototypedBy(JsonBindingConfig.class)
public interface JsonBinding extends RuntimeType.Api<JsonBindingConfig> {

    static JsonBinding create() {
        return builder().build();
    }

    static JsonBindingConfig.Builder builder() {
        return JsonBindingConfig.builder();
    }

    static JsonBinding create(JsonBindingConfig config) {
        JsonBindingImpl jsonBinding = new JsonBindingImpl(config);
        Set<JsonConfigurable> processed = new HashSet<>();
        for (TypedJsonSerializer<?> serializer : config.serializers()) {
            if (serializer instanceof JsonConfigurable configurable) {
                configurable.configure(jsonBinding);
                processed.add(configurable);
            }
        }
        for (TypedJsonDeserializer<?> deserializer : config.deserializers()) {
            if (deserializer instanceof JsonConfigurable configurable
                    && !processed.contains(deserializer)) {
                configurable.configure(jsonBinding);
            }
        }
        return jsonBinding;
    }

    static JsonBinding create(Consumer<JsonBindingConfig.Builder> consumer) {
        JsonBindingConfig.Builder builder = builder().update(consumer);
        return create(builder.buildPrototype());
    }

    static String serialize(Object obj) {
        return JsonBindingImpl.DEFAULT_INSTANCE.toJson(obj);
    }

    static <T> String serialize(T obj, Class<T> type) {
        return JsonBindingImpl.DEFAULT_INSTANCE.toJson(obj, type);
    }

    static <T> String serialize(T obj, GenericType<T> type) {
        return JsonBindingImpl.DEFAULT_INSTANCE.toJson(obj, type);
    }

    static <T> T deserialize(String jsonStr, Class<T> type) {
        return JsonBindingImpl.DEFAULT_INSTANCE.fromJson(jsonStr, type);
    }

    static <T> T deserialize(String jsonStr, GenericType<T> type) {
        return JsonBindingImpl.DEFAULT_INSTANCE.fromJson(jsonStr, type);
    }

    String toJson(Object obj);

    <T> String toJson(T obj, Class<T> type);

    <T> String toJson(T obj, GenericType<T> type);

    <T> T fromJson(String jsonStr, Class<T> type);

    <T> T fromJson(String jsonStr, GenericType<T> type);

}
