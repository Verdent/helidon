package io.helidon.json.binding;

import io.helidon.json.processor.JsonParser;

public interface JsonDeserializer<T> {

    T deserialize(JsonParser parser);

    default T deserializeNull() {
        return null;
    }

}
