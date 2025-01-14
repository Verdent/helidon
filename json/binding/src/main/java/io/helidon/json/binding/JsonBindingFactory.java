package io.helidon.json.binding;

import java.lang.reflect.Type;

public interface JsonBindingFactory<T> {

//    ConfigurableJsonDeserializer<T>  createDeserializer(JsonBinding jsonBinding, Type type);
//    ConfigurableJsonSerializer<T>  createSerializer(JsonBinding jsonBinding, Type type);

    JsonDeserializer<T>  createDeserializer(JsonBindingConfigurer jsonBindingConfigurer, Type type);
    JsonSerializer<T>  createSerializer(JsonBindingConfigurer jsonBindingConfigurer, Type type);

}