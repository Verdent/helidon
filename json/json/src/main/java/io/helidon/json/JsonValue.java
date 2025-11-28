package io.helidon.json;

/**
 * TODO javadoc
 */
public sealed abstract class JsonValue
        permits JsonArray, JsonBoolean, JsonNull, JsonNumber, JsonObject, JsonString, JsonControlValue {

    public abstract JsonValueType type();

    public abstract void toJson(Generator generator);

    abstract byte jsonStartChar();

    public JsonString asString() {
        if (type() == JsonValueType.STRING) {
            return (JsonString) this;
        }
        throw new JsonException("Json value is not a string, but rather " + type());
    }

    public JsonNumber asNumber() {
        if (type() == JsonValueType.NUMBER) {
            return (JsonNumber) this;
        }
        throw new JsonException("Json value is not a number, but rather " + type());
    }

    public JsonObject asObject() {
        if (type() == JsonValueType.OBJECT) {
            return (JsonObject) this;
        }
        throw new JsonException("Json value is not an object, but rather " + type());
    }

    public JsonArray asArray() {
        if (type() == JsonValueType.ARRAY) {
            return (JsonArray) this;
        }
        throw new JsonException("Json value is not an array, but rather " + type());
    }

    public JsonBoolean asBoolean() {
        if (type() == JsonValueType.BOOLEAN) {
            return (JsonBoolean) this;
        }
        throw new JsonException("Json value is not a boolean, but rather " + type());
    }
}
