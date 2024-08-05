package io.helidon.json.binding;

import io.helidon.json.processor.JsonParser;

public interface JsonDeserializer<T> {

    T fromJson(JsonParser parser);

}
