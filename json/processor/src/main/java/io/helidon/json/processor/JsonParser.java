package io.helidon.json.processor;

/**
 * TODO javadoc
 */
public interface JsonParser {

    static JsonParser create(String json) {
        return new JsonParserImpl(json);
//        return new StreamJsonParser(new ByteArrayInputStream(json.getBytes()));
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
    int readInt();
    long readLong();
    boolean checkNull();
    boolean checkTrue();
    boolean checkFalse();
    void skip();
    void byteRollback();

}
