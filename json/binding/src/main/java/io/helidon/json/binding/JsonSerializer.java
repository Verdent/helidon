package io.helidon.json.binding;

import io.helidon.common.GenericType;
import io.helidon.json.processor.Generator;

public interface JsonSerializer<T> {

    GenericType<T> type();

    void toJson(Generator generator, T instance);

}
