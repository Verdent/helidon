package io.helidon.json.binding;

public interface BindingFactorySerializer<T> extends JsonSerializer<T> {

    void configure(JsonBindingConfigurer jsonBindingConfigurer, JsonContext jsonContext);

}
