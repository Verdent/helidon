package io.helidon.json.binding;

import io.helidon.common.GenericType;
import io.helidon.json.Generator;
import io.helidon.json.JsonException;

public interface JsonSerializer<T> {

    void serialize(Generator generator, T instance, boolean writeNulls);

    default void serializeNull(Generator generator) {
        generator.writeNull();
    }

    GenericType<T> type();

    default void configure(JsonBindingConfigurator jsonBindingConfigurator) {
    }

    default boolean isMapKeySerializer() {
        return false;
    }

    default String serializeAsMapKey(T instance) {
        throw new JsonException(instance.getClass().getName() + " is not supported for a Map key serialization");
    }

}
