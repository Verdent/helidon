package io.helidon.json.binding;

import io.helidon.common.GenericType;
import io.helidon.json.JsonParser;

public interface JsonDeserializer<T> {

    T deserialize(JsonParser parser);

    default T deserializeNull() {
        return null;
    }

    GenericType<T> type();

    default void configure(JsonBindingConfigurator jsonBindingConfigurator) {
    }

}
