package io.helidon.json;

public final class JsonString extends JsonValue {

    private final byte[] buffer;
    private final int start;
    private final int length;
    private String resolvedValue;

    private JsonString(byte[] buffer, int start, int length) {
        this.buffer = buffer;
        this.start = start;
        this.length = length;
    }
    private JsonString(String value) {
        this.buffer = JsonValues.EMPTY_BYTES;
        this.start = -1;
        this.length = value.length();
        this.resolvedValue = value;
    }

    public static JsonString create(String value) {
        return new JsonString(value);
    }

    static JsonString create(byte[] buffer, int start, int length) {
        return new JsonString(buffer, start, length);
    }

    @Override
    byte jsonStartChar() {
        return '"';
    }

    public String value() {
        if (resolvedValue == null) {
            resolveValue();
        }
        return resolvedValue;
    }

    String resolveValue() {
        resolvedValue = new String(buffer, start, length);
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

    @Override
    public void toJson(Generator generator) {
        generator.write(value());
    }
}
