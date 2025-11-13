package io.helidon.json.processor;

final class JsonControlValue extends JsonValue {

    private final byte controlChar;

    JsonControlValue(char controlChar) {
        this.controlChar = (byte) controlChar;
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.CONTROL;
    }

    @Override
    public void toJson(Generator generator) {
        throw new UnsupportedOperationException();
    }

    @Override
    byte jsonStartChar() {
        return controlChar;
    }

    @Override
    public String toString() {
        return "" + (char) controlChar;
    }
}
