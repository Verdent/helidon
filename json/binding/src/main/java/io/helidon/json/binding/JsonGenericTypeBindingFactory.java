package io.helidon.json.binding;

import io.helidon.common.GenericType;

public interface JsonGenericTypeBindingFactory<T> {

    JsonDeserializer<T>  createDeserializer(JsonBinding jsonBinding, GenericType<T> type);
    JsonSerializer<T>  createSerializer(JsonBinding jsonBinding, GenericType<T> type);

}