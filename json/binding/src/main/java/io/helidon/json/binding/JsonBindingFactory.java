package io.helidon.json.binding;

import java.lang.reflect.Type;

public interface JsonBindingFactory<T> {

    JsonDeserializer<T>  createDeserializer(JsonBinding jsonBinding, Type type);
    JsonSerializer<T>  createSerializer(JsonBinding jsonBinding, Type type);

}