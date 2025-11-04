package io.helidon.json.binding;

import java.lang.reflect.Type;

import io.helidon.common.GenericType;

public interface JsonBindingConfigurator {

    <T> JsonDeserializer<T> getDeserializer(Type type);

    <T> JsonDeserializer<T> getDeserializer(Type type, JsonContext jsonContext);

    <T> JsonDeserializer<T> getDeserializer(Class<T> type);

    <T> JsonDeserializer<T> getDeserializer(Class<T> type, JsonContext jsonContext);

    <T> JsonDeserializer<T> getDeserializer(GenericType<?> type);

    <T> JsonDeserializer<T> getDeserializer(GenericType<?> type, JsonContext jsonContext);

    <T> JsonSerializer<T> getSerializer(Type type);

    <T> JsonSerializer<T> getSerializer(Type type, JsonContext jsonContext);

    <T> JsonSerializer<T> getSerializer(Class<T> type);

    <T> JsonSerializer<T> getSerializer(Class<T> type, JsonContext jsonContext);

    <T> JsonSerializer<T> getSerializer(GenericType<?> type);

    <T> JsonSerializer<T> getSerializer(GenericType<?> type, JsonContext jsonContext);

}
