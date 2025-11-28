package io.helidon.json.binding;

import java.lang.reflect.Type;

import io.helidon.common.GenericType;

public interface JsonBindingConfigurator {

    <T> JsonDeserializer<T> deserializer(Type type);

    <T> JsonDeserializer<T> deserializer(Class<T> type);

    <T> JsonDeserializer<T> deserializer(GenericType<T> type);

    <T> JsonSerializer<T> serializer(Type type);

    <T> JsonSerializer<T> serializer(Class<T> type);

    <T> JsonSerializer<T> serializer(GenericType<T> type);

}
