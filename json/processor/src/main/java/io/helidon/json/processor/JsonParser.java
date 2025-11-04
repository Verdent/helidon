package io.helidon.json.processor;

import java.io.InputStream;

/**
 * TODO javadoc
 */
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

    boolean hasNext();
    byte readNextByte();
    byte nextToken();
    byte lastByte();

    JsonValue readJsonValue();

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

    /**
     * The next byte in the buffer, without changing the current buffer position.
     * If no byte is available, throws an {@link JsonException}.
     *
     * @return next byte
     */
//    byte peek();

}
