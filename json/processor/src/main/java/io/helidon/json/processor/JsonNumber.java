package io.helidon.json.processor;

/**
 * TODO javadoc
 */
public class JsonNumber implements JsonValue {

    private final byte[] buffer;
    private final int start;
    private Double value;

    private JsonNumber(byte[] buffer, int start) {
        this.buffer = buffer;
        this.start = start;
    }

    public static JsonNumber create(byte[] buffer, int start) {
        return new JsonNumber(buffer, start);
    }

    public double value() {
        if (value == null) {
            CachedParser cachedParser = JsonParserCache.getCachedParser();
            ReusableJsonParser parser = cachedParser.get();
            resolveValue(parser);
            cachedParser.set(parser);
        }
        return value;
    }

    void resolveValue(ReusableJsonParser parser) {
        parser.reset(buffer, start);
        value = parser.readAsDouble();
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.NUMBER;
    }
}
