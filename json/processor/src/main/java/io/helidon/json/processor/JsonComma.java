package io.helidon.json.processor;

final class JsonComma extends JsonValue {
    @Override
    public JsonValueType type() {
        return JsonValueType.CONTROL;
    }

    @Override
    public void toJson(Generator generator) {
        throw new UnsupportedOperationException();
    }
}
