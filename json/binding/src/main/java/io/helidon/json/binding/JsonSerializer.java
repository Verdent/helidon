package io.helidon.json.binding;

import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;

public interface JsonSerializer<T> {

    void serialize(Generator generator, T instance, boolean writeNulls);

    default void serializeNull(Generator generator) {
        generator.writeNull();
    }

    default void configure(JsonBindingConfigurator jsonBindingConfigurator) {
    }

    default boolean isMapKeySerializer() {
        return false;
    }

    default String serializeAsMapKey(T instance) {
        throw new JsonException(instance.getClass().getName() + " is not supported for a Map key serialization");
    }

}
