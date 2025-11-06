package io.helidon.json.processor;

/**
 * TODO javadoc
 */
public sealed interface JsonValue permits JsonArray, JsonBoolean, JsonNull, JsonNumber, JsonObject, JsonString {

    JsonValueType type();

    void toJson(Generator generator);

    default JsonString asString() {
        if (type() == JsonValueType.STRING) {
            return (JsonString) this;
        }
        throw new JsonException("Json value is not a string, but rather " + type());
    }

    default JsonNumber asNumber() {
        if (type() == JsonValueType.NUMBER) {
            return (JsonNumber) this;
        }
        throw new JsonException("Json value is not a number, but rather " + type());
    }

    default JsonObject asObject() {
        if (type() == JsonValueType.OBJECT) {
            return (JsonObject) this;
        }
        throw new JsonException("Json value is not an object, but rather " + type());
    }

    default JsonBoolean asBoolean() {
        if (type() == JsonValueType.BOOLEAN) {
            return (JsonBoolean) this;
        }
        throw new JsonException("Json value is not a boolean, but rather " + type());
    }
}
