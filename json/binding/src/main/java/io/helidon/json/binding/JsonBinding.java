package io.helidon.json.binding;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import io.helidon.builder.api.RuntimeType;

@RuntimeType.PrototypedBy(JsonBindingConfig.class)
public final class JsonBinding implements RuntimeType.Api<JsonBindingConfig> {

    private final JsonBindingConfig config;
    private final Map<Class<?>, JsonSerializer<?>> serializers;
    private final Map<Class<?>, JsonDeserializer<?>> deserializers;

    private JsonBinding(JsonBindingConfig config) {
        this.config = config;
        this.serializers = Map.copyOf(config.serializers());
        this.deserializers = Map.copyOf(config.deserializers());
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
    public <T> JsonDeserializer<T> getDeserializer(Class<T> type) {
        return (JsonDeserializer<T>) deserializers.get(type);
    }

}
