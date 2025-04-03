package io.helidon.json.binding;

import io.helidon.common.GenericType;
import io.helidon.json.processor.JsonParser;

class DefaultTypedJsonDeserializer<T> implements TypedJsonDeserializer<T> {

    private final GenericType<T> type;
    private final JsonDeserializer<T> deserializer;

    DefaultTypedJsonDeserializer(GenericType<T> type, JsonDeserializer<T> deserializer) {
        this.type = type;
        this.deserializer = deserializer;
    }

    @Override
    public GenericType<T> type() {
        return type;
    }

    @Override
    public T fromJsonValue(JsonParser parser) {
        return deserializer.fromJson(parser);
    }
}
