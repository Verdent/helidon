package io.helidon.json.binding;

import java.util.Set;

import io.helidon.common.GenericType;

public interface JsonBindingFactory<T> {

    JsonDeserializer<T> createDeserializer(Class<? extends T> type);
    JsonDeserializer<T> createDeserializer(GenericType<? extends T> type);
    JsonSerializer<T> createSerializer(Class<? extends T> type);
    JsonSerializer<T> createSerializer(GenericType<? extends T> type);

    Set<Class<?>> supportedTypes();

}