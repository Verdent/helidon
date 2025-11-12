package io.helidon.json.processor;

import java.nio.charset.StandardCharsets;

class JsonValueParser implements JsonParser {

    private final JsonValue[] values = new JsonValue[500];
    private JsonValue current;
    private int index = 0;
    private byte lastByte;
    private boolean theFirstValue = true;

    JsonValueParser(JsonValue jsonValue) {
        this.current = jsonValue;
    }

    @Override
    public boolean hasNext() {
        return index < 0;
    }

    @Override
    public byte readNextByte() {
        return nextToken();
    }

    @Override
    public byte nextToken() {
        if (current.type() == JsonValueType.OBJECT) {
            JsonObject object = current.asObject();
        } else if (current.type() == JsonValueType.ARRAY) {
            JsonArray array = current.asArray();
            int size = array.values().size();
            for (JsonValue value : array.values()) {
                values[index + --size] = value;
            }
            index += array.values().size() - 1;
        }
        if (index >= 0) {
            current = values[index--];
            values[index + 1] = null;
            return switch (current.type()) {
                case NULL -> lastByte = 'n';
                case BOOLEAN -> {
                    if (current.asBoolean().value()) {
                        yield lastByte = 't';
                    }
                    yield lastByte = 'f';
                }
                case STRING -> lastByte = '"';
                case NUMBER -> lastByte = '1';
                case ARRAY -> lastByte = '[';
                case OBJECT -> lastByte = '{';
            };
        }

        throw new UnsupportedOperationException("CHANGE");
    }

    @Override
    public byte lastByte() {
        return switch (current.type()) {
            case NULL -> 'n';
            case BOOLEAN -> {
                if (current.asBoolean().value()) {
                    yield 't';
                }
                yield 'f';
            }
            case STRING -> '"';
            case NUMBER -> '1';
            case ARRAY -> '[';
            case OBJECT -> '{';
        };
    }

    @Override
    public JsonValue readJsonValue() {
        return current;
    }

    @Override
    public JsonObject readJsonObject() {
        return current.asObject();
    }

    @Override
    public JsonArray readJsonArray() {
        return current.asArray();
    }

    @Override
    public JsonString readJsonString() {
        return current.asString();
    }

    @Override
    public JsonNumber readJsonNumber() {
        return current.asNumber();
    }

    @Override
    public String readString() {
        return current.asString().value();
    }

    @Override
    public int readStringAsHash() {
        String key = current.asString().value();
        long fnvHash = 2166136261L;
        byte[] array = key.getBytes(StandardCharsets.UTF_8);
        for (byte b : array) {
            fnvHash ^= b;
            fnvHash *= 16777619;
        }
        return (int) fnvHash;
    }

    @Override
    public char[] readNumberAsArray() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean readAsBoolean() {
        return current.asBoolean().value();
    }

    @Override
    public byte readAsByte() {
        throw new UnsupportedOperationException();
    }

    @Override
    public short readAsShort() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int readAsInt() {
        return current.asNumber().intValue();
    }

    @Override
    public long readAsLong() {
        return current.asNumber().intValue();
    }

    @Override
    public float readAsFloat() {
        return (float) current.asNumber().doubleValue();
    }

    @Override
    public double readAsDouble() {
        return current.asNumber().doubleValue();
    }

    @Override
    public boolean checkNull() {
        return current.type() == JsonValueType.NULL;
    }

    @Override
    public void skip() {
        current = null;
    }

    @Override
    public void byteRollback() {
        throw new UnsupportedOperationException("This is unsupported");
    }
}
