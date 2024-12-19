package io.helidon.json.binding;

import java.util.Map;
import java.util.function.Consumer;

import io.helidon.builder.api.RuntimeType;
import io.helidon.common.types.TypeName;

@RuntimeType.PrototypedBy(JsonBindingConfig.class)
public final class JsonBinding implements RuntimeType.Api<JsonBindingConfig> {

    private final JsonBindingConfig config;
    private final Map<Class<?>, JsonSerializer<?>> serializers;
    private final Map<TypeName, JsonSerializer<?>> serializersTypeName;
    private final Map<Class<?>, JsonDeserializer<?>> deserializers;
    private final Map<TypeName, JsonDeserializer<?>> deserializersTypeName;

    private JsonBinding(JsonBindingConfig config) {
        this.config = config;
        this.serializers = Map.copyOf(config.serializers());
        this.serializersTypeName = Map.of();
        this.deserializers = Map.copyOf(config.deserializers());
        this.deserializersTypeName = Map.of();
    }

    public static JsonBindingConfig.Builder builder() {
        return JsonBindingConfig.builder();
    }

    public static JsonBinding create(JsonBindingConfig config) {
        return new JsonBinding(config);
    }

    static JsonBinding create(Consumer<JsonBindingConfig.Builder> consumer) {
        JsonBindingConfig.Builder builder = builder().update(consumer);
        return create(builder.buildPrototype());
    }

    @Override
    public JsonBindingConfig prototype() {
        return config;
    }

    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Class<T> type) {
        return (JsonSerializer<T>) serializers.get(type);
    }

    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(TypeName type) {
        return (JsonSerializer<T>) serializersTypeName.get(type);
    }

    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Class<T> type) {
        return (JsonDeserializer<T>) deserializers.get(type);
    }

    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(TypeName type) {
        return (JsonDeserializer<T>) deserializersTypeName.get(type);
    }

}
