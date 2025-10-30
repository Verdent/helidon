package io.helidon.json.processor;

public class JsonArray implements JsonValue {
    @Override
    public JsonValueType type() {
        return JsonValueType.ARRAY;
    }
}
