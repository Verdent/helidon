package io.helidon.json.processor;

public class JsonString implements JsonValue {

    private final char[] source;

    public JsonString(char[] source) {
        this.source = source;
    }

    public String resolveString() {
        throw new UnsupportedOperationException();
    }
}
