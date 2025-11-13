package io.helidon.json.processor;

import java.nio.charset.StandardCharsets;
import java.util.Set;

class JsonValueParser implements JsonParser {

    private final JsonValue[] values = new JsonValue[500];
    private JsonValue current;
    private int index = 0;
    private byte lastByte;

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
        if (current != null) {
            if (current.type() == JsonValueType.OBJECT) {
                JsonObject object = current.asObject();
                Set<JsonString> keys = object.keys();
                //We need to calculate how many values we need to add + how many commas
                // key size needs to be multiplied by 4, because for every key, nad value we will add : and , (-1 for the last object)
                int size = (keys.size() * 4) - 1;
                if (index > 0) {
                    //We are having some values before this one. index need to be raised to prevet overwriting.
                    index++;
                }
                values[index++] = new JsonControlValue('}');
                for (JsonString key : keys) {
                    values[index + --size] = key;
                    values[index + --size] = new JsonControlValue(':');
                    values[index + --size] = object.value(key.value(), JsonNull.instance());
                    if (size > 0) {
                        values[index + --size] = new JsonControlValue(',');
                    }
                }
                index += (keys.size() * 4) - 2;
            } else if (current.type() == JsonValueType.ARRAY) {
                JsonArray array = current.asArray();
                //We need to calculate how many values we need to add + how many commas
                int size = (array.values().size() * 2) - 1;
                if (index > 0) {
                    //We are having some values before this one. index need to be raised to prevet overwriting.
                    index++;
                }
                values[++index] = new JsonControlValue(']');
                for (JsonValue value : array.values()) {
                    values[index + --size] = value;
                    if (size > 0) {
                        values[index + --size] = new JsonControlValue(',');
                    }
                }
                index += (array.values().size() * 2) - 2;
            }
        }
        if (index >= 0) {
            current = values[index];
            values[index--] = null;
            return current.jsonStartChar();
        }
        throw new UnsupportedOperationException("No more JSON Values available");
    }

    @Override
    public byte lastByte() {
        return current.jsonStartChar();
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
