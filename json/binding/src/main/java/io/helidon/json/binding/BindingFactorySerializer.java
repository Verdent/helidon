package io.helidon.json.binding;

import java.lang.reflect.Type;

public interface BindingFactorySerializer<T> extends JsonSerializer<T> {

    void configure(JsonBindingConfigurer jsonBindingConfigurer);

}
