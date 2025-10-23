package io.helidon.json.processor;

public class JsonNull implements JsonValue {

    private static final JsonNull INSTANCE = new JsonNull();

    private JsonNull() {
    }

    public static JsonNull instance() {
        return INSTANCE;
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.NULL;
    }

}
