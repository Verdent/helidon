package io.helidon.json.binding;

public interface BindingFactoryDeserializer<T> extends JsonDeserializer<T> {

    void configure(JsonBindingConfigurator jsonBindingConfigurator, JsonContext jsonContext);

}
