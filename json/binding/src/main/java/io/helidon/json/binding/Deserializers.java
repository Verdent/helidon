package io.helidon.json.binding;

import io.helidon.json.processor.JsonParser;

public final class Deserializers {

    public static <T> T deserialize(JsonParser parser, JsonDeserializer<T> deserializer) {
        if (parser.checkNull()) {
            return deserializer.deserializeNull();
        }
        return deserializer.deserialize(parser);
    }

}
