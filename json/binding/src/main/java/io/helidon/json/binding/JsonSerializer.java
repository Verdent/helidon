package io.helidon.json.binding;

import io.helidon.json.processor.Generator;

public interface JsonSerializer<T> {

    void toJson(Generator generator, T instance);

}
