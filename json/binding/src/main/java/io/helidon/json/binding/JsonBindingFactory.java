package io.helidon.json.binding;

import java.lang.reflect.Type;

public interface JsonBindingFactory<T> {

    BindingFactoryDeserializer<T> createDeserializer(Type type);
    BindingFactorySerializer<T> createSerializer(Type type);

}