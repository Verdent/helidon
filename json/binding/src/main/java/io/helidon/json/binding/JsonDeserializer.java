package io.helidon.json.binding;

import io.helidon.json.processor.JsonParser;

public interface JsonDeserializer<T> {

    default T fromJson(JsonParser parser) {
        if (parser.checkNull()) {
            return fromNull();
        }
        return fromJsonValue(parser);
    }

    T fromJsonValue(JsonParser parser);

    default T fromNull() {
        return null;
    }

}
