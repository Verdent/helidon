package io.helidon.json.binding;

import io.helidon.builder.api.Prototype;
import io.helidon.common.GenericType;

class JsonBindingConfigCustomMethods {

    private JsonBindingConfigCustomMethods() {
    }

    @Prototype.BuilderMethod
    static <T> void addConverter(JsonBindingConfig.BuilderBase<?, ?> builder, TypedJsonConverter<T> converter) {
        builder.addSerializer(converter)
                .addDeserializer(converter);
    }

    @Prototype.BuilderMethod
    static <T> void addConverter(JsonBindingConfig.BuilderBase<?, ?> builder, Class<T> type, JsonConverter<T> converter) {
        GenericType<T> genericType = GenericType.create(type);
        builder.addSerializer(new DefaultTypedJsonSerializer<>(genericType, converter))
                .addDeserializer(new DefaultTypedJsonDeserializer<>(genericType, converter));
    }

    @Prototype.BuilderMethod
    static <T> void addConverter(JsonBindingConfig.BuilderBase<?, ?> builder,
                                 GenericType<T> genericType,
                                 JsonConverter<T> converter) {
        builder.addSerializer(new DefaultTypedJsonSerializer<>(genericType, converter))
                .addDeserializer(new DefaultTypedJsonDeserializer<>(genericType, converter));
    }

    @Prototype.BuilderMethod
    static <T> void addSerializer(JsonBindingConfig.BuilderBase<?, ?> builder, Class<T> type, JsonSerializer<T> serializer) {
        GenericType<T> genericType = GenericType.create(type);
        builder.addSerializer(new DefaultTypedJsonSerializer<>(genericType, serializer));
    }

    @Prototype.BuilderMethod
    static <T> void addSerializer(JsonBindingConfig.BuilderBase<?, ?> builder,
                                  GenericType<T> genericType,
                                  JsonSerializer<T> serializer) {
        builder.addSerializer(new DefaultTypedJsonSerializer<>(genericType, serializer));
    }

    @Prototype.BuilderMethod
    static <T> void addDeserializer(JsonBindingConfig.BuilderBase<?, ?> builder, Class<T> type, JsonDeserializer<T> deserializer) {
        GenericType<T> genericType = GenericType.create(type);
        builder.addDeserializer(new DefaultTypedJsonDeserializer<>(genericType, deserializer));
    }

    @Prototype.BuilderMethod
    static <T> void addDeserializer(JsonBindingConfig.BuilderBase<?, ?> builder,
                                    GenericType<T> genericType,
                                    JsonDeserializer<T> deserializer) {
        builder.addDeserializer(new DefaultTypedJsonDeserializer<>(genericType, deserializer));
    }

}
