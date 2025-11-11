package io.helidon.json.binding;

import java.math.BigDecimal;

import io.helidon.common.GenericType;
import io.helidon.json.processor.JsonParser;

public interface JsonDeserializer<T> {

    T deserialize(JsonParser parser);

    default T deserializeNull() {
        return null;
    }

    GenericType<T> type();

    default void configure(JsonBindingConfigurator jsonBindingConfigurator) {
    }

}
