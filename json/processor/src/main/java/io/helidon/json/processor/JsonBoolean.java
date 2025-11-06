package io.helidon.json.processor;

public final class JsonBoolean implements JsonValue {

    private final boolean value;

    private JsonBoolean(boolean value) {
        this.value = value;
    }

    public static JsonBoolean create(boolean value) {
        return new JsonBoolean(value);
    }

    public boolean value() {
        return value;
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.BOOLEAN;
    }

    @Override
    public void toJson(Generator generator) {
        generator.writeValue(value);
    }

}
