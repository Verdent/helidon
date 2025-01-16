package io.helidon.json.binding;

import java.lang.reflect.Type;

public interface BindingFactoryDeserializer<T> extends JsonDeserializer<T> {

    void configure(JsonBindingConfigurer jsonBindingConfigurer, Type type);

}
