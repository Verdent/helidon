package io.helidon.json.processor;

import java.io.InputStream;

/**
 * TODO javadoc
 */
public interface JsonParser {

    static JsonParser create(String json) {
        return new JsonParserImpl(json);
//        return new StreamJsonParser(new ByteArrayInputStream(json.getBytes()));
    }

    static JsonParser create(InputStream inputStream) {
        return new JsonStreamParser(inputStream);
    }

    static JsonParser create() {
        return new JsonParserImpl();
    }

    byte readNextByte();
    byte nextToken();
    byte lastByte();

    JsonObject readObject();

    String readString();

    int readStringAsHash();

    JsonNumber readJsonNumber();
    char[] readNumberAsArray();
    boolean readAsBoolean();
    byte readAsByte();
    short readAsShort();
    int readAsInt();
    long readAsLong();
    float readAsFloat();
    double readAsDouble();
    boolean checkNull();
    boolean checkTrue();
    boolean checkFalse();
    void skip();
    void byteRollback();

}
