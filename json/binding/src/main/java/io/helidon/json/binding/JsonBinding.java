package io.helidon.json.binding;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import io.helidon.builder.api.RuntimeType;
import io.helidon.common.GenericType;
import io.helidon.json.processor.JsonObject;
import io.helidon.json.processor.JsonValue;

@RuntimeType.PrototypedBy(JsonBindingConfig.class)
public interface JsonBinding extends RuntimeType.Api<JsonBindingConfig> {

    static JsonBinding create() {
        return builder().build();
    }

    static JsonBindingConfig.Builder builder() {
        return JsonBindingConfig.builder();
    }

    @SuppressWarnings("SuspiciousMethodCalls")
    static JsonBinding create(JsonBindingConfig config) {
        JsonBindingImpl jsonBinding = new JsonBindingImpl(config);
        for (JsonSerializer<?> serializer : config.serializers()) {
            serializer.configure(jsonBinding);
        }
        for (JsonDeserializer<?> deserializer : config.deserializers()) {
            if (config.serializers().contains(deserializer)) {
                continue;
            }
            deserializer.configure(jsonBinding);
        }
        return jsonBinding;
    }

    static JsonBinding create(Consumer<JsonBindingConfig.Builder> consumer) {
        JsonBindingConfig.Builder builder = builder().update(consumer);
        return create(builder.buildPrototype());
    }

    String serialize(Object obj);

    <T> String serialize(T obj, Class<? super T> type);

    <T> String serialize(T obj, GenericType<? super T> type);

    void serialize(OutputStream outputStream, Object obj);

    <T> void serialize(OutputStream outputStream, T obj, Class<? super T> type);

    <T> void serialize(OutputStream outputStream, T obj, GenericType<? super T> type);

    <T> T deserialize(byte[] bytes, Class<T> type);

    <T> T deserialize(byte[] bytes, GenericType<T> type);

    <T> T deserialize(String jsonStr, Class<T> type);

    <T> T deserialize(String jsonStr, GenericType<T> type);

    <T> T deserialize(InputStream inputStream, Class<T> type);

    <T> T deserialize(InputStream inputStream, GenericType<T> type);

    <T> T deserialize(JsonValue jsonValue, Class<T> type);

    <T> T deserialize(JsonValue jsonValue, GenericType<T> type);

}
