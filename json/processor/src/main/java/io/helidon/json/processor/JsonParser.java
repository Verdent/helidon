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

    static JsonParser empty() {
        return new JsonParserImpl();
    }

    static JsonParser emptyStream() {
        return new JsonStreamParser();
    }
    boolean hasNext();
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
    void skip();
    void byteRollback();

}
