package io.helidon.json.api;

public interface JsonDeserializer<T> {

    default T fromJson(JsonParser parser) {
        return fromJson(parser.readObject());
    }

    T fromJson(JsonObject value);

}
