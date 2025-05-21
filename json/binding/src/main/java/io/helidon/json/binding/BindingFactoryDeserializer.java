package io.helidon.json.binding;

public interface BindingFactoryDeserializer<T> extends JsonDeserializer<T> {

    void configure(JsonBindingConfigurer jsonBindingConfigurer, JsonContext jsonContext);

}
