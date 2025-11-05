package io.helidon.json.binding;

/**
 * TODO javadoc
 */
public interface TypedJsonConverter<T> extends TypedJsonSerializer<T>, TypedJsonDeserializer<T> {

    default void configure(JsonBindingConfigurator jsonBindingConfigurator) {
    }

}
