package io.helidon.json;

public final class JsonNull extends JsonValue {

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

    @Override
    public void toJson(Generator generator) {
        generator.writeNull();
    }

    @Override
    byte jsonStartChar() {
        return 'n';
    }

}
