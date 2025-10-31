package io.helidon.json.processor;

public class JsonArray implements JsonValue {

    private final byte[] buffer;
    private final int start;

    public JsonArray(byte[] buffer, int start) {
        this.buffer = buffer;
        this.start = start;
    }

    public static JsonArray create(byte[] buffer, int start) {
        return new JsonArray(buffer, start);
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.ARRAY;
    }
}
