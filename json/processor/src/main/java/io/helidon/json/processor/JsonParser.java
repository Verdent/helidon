package io.helidon.json.processor;

import java.io.InputStream;

public interface JsonParser {

    static JsonParser create(String json) {
        return new ArrayJsonParser(json);
    }

    static JsonParser create(InputStream inputStream) {
        return new JsonStreamParser(inputStream);
    }

    static JsonParser create(InputStream inputStream, int bufferSize) {
        return new JsonStreamParser(inputStream, bufferSize);
    }

    static JsonParser create(JsonValue value) {
        return new JsonValueParser(value);
    }

    static JsonParser empty() {
        return new ArrayJsonParser();
    }

    static JsonParser emptyStream() {
        return new JsonStreamParser();
    }

    boolean hasNext();

    byte readNextByte();

    byte nextToken();

    byte lastByte();

    JsonValue readJsonValue();

    JsonObject readJsonObject();

    JsonArray readJsonArray();

    JsonString readJsonString();

    JsonNumber readJsonNumber();

    String readString();

    int readStringAsHash();

    char[] readNumberAsArray();

    boolean readAsBoolean();

    byte readAsByte();

    short readAsShort();

    int readAsInt();

    long readAsLong();

    float readAsFloat();

    double readAsDouble();

    boolean checkNull();

    void skip();

    void byteRollback();

}
