package io.helidon.json.binding;

import java.lang.reflect.Type;

import io.helidon.builder.api.Prototype;
import io.helidon.common.GenericType;

class JsonBindingConfigCustomMethods {

    private JsonBindingConfigCustomMethods() {
    }

    @Prototype.BuilderMethod
    static <T> void addSerializer(JsonBindingConfig.BuilderBase<?, ?> builder, Class<T> type, JsonSerializer<T> serializer) {
        GenericType<T> genericType = GenericType.create(type);
        builder.addSerializer(new DefaultTypedJsonSerializer<>(genericType, serializer));
    }

    @Prototype.BuilderMethod
    static <T> void addSerializer(JsonBindingConfig.BuilderBase<?, ?> builder, Type type, JsonSerializer<T> serializer) {
        GenericType<T> genericType = GenericType.create(type);
        builder.addSerializer(new DefaultTypedJsonSerializer<>(genericType, serializer));
    }

    @Prototype.BuilderMethod
    static <T> void addDeserializer(JsonBindingConfig.BuilderBase<?, ?> builder, Class<T> type, JsonDeserializer<T> deserializer) {
        GenericType<T> genericType = GenericType.create(type);
        builder.addDeserializer(new DefaultTypedJsonDeserializer<>(genericType, deserializer));
    }

    @Prototype.BuilderMethod
    static <T> void addDeserializer(JsonBindingConfig.BuilderBase<?, ?> builder, Type type, JsonDeserializer<T> deserializer) {
        GenericType<T> genericType = GenericType.create(type);
        builder.addDeserializer(new DefaultTypedJsonDeserializer<>(genericType, deserializer));
    }

}
