package io.helidon.json.binding;

import java.lang.reflect.Type;

public interface JsonBindingFactory<T> {

    JsonDeserializer<T> createDeserializer(Type type);
    JsonSerializer<T> createSerializer(Type type);

}