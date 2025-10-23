package io.helidon.json.processor;

public final class JsonString implements JsonValue {

    private final byte[] buffer;
    private final int start;
    private String resolvedValue;

    private JsonString(byte[] buffer, int start) {
        this.buffer = buffer;
        this.start = start;
    }

    public static JsonString create(byte[] buffer, int start) {
        return new JsonString(buffer, start);
    }

    public String value() {
        if (resolvedValue == null) {
            CachedParser cachedParser = JsonParserCache.getCachedParser();
            ReusableJsonParser parser = cachedParser.get();
            resolveValue(parser);
            cachedParser.set(parser);
        }
        return resolvedValue;
    }

    String resolveValue(ReusableJsonParser parser) {
        parser.reset(buffer, start);
        resolvedValue = parser.readString();
        return resolvedValue;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        String value = value();
        if (obj instanceof String string) {
            return value.equals(string);
        } else if (obj instanceof JsonString jsonString) {
            return jsonString.value().equals(value);
        }
        return false;
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.STRING;
    }
}
