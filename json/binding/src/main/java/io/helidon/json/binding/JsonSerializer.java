package io.helidon.json.binding;

import io.helidon.json.processor.Generator;

public interface JsonSerializer<T> {

    void serialize(Generator generator, T instance, boolean writeNulls);

    default void serializeNull(Generator generator) {
        generator.writeNull();
    }

}
