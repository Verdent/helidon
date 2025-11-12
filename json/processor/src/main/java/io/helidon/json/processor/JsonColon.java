package io.helidon.json.processor;

final class JsonColon extends JsonValue {
    @Override
    public JsonValueType type() {
        return JsonValueType.CONTROL;
    }

    @Override
    public void toJson(Generator generator) {
        throw new UnsupportedOperationException();
    }
}
