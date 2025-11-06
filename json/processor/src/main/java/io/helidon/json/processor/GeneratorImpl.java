package io.helidon.json.processor;

import java.io.OutputStream;

class GeneratorImpl implements Generator {

    private static final byte QUOTES = '"';
    private static final byte COMMA = ',';
    private static final byte COLON = ':';
    private static final byte ARRAY_START = '[';
    private static final byte ARRAY_END = ']';
    private static final byte OBJECT_START = '{';
    private static final byte OBJECT_END = '}';

    private final OutputStream outputStream;
    private final byte[] osBuffer = new byte[5120];
    private int index = 0;

    GeneratorImpl(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    @Override
    public void writeKey(String key) {
        writeQuoted(key);
        writeColon();
    }

    @Override
    public void write(String key, String value) {
        writeQuoted(key);
        writeColon();
        writeQuoted(value);
    }

    @Override
    public void write(String key, int value) {
        writeQuoted(key);
        writeColon();
        writeValue(value);
    }

    @Override
    public void write(String key, long value) {
        writeQuoted(key);
        writeColon();
        writeValue(value);
    }

    @Override
    public void write(String key, float value) {
        writeQuoted(key);
        writeColon();
        writeValue(value);
    }

    @Override
    public void write(String key, double value) {
        writeQuoted(key);
        writeColon();
        writeValue(value);
    }

    @Override
    public void write(String key, boolean value) {
        writeQuoted(key);
        writeColon();
        writeValue(value);
    }

    @Override
    public void write(String key, JsonObject value) {
        writeQuoted(key);
        writeColon();
        writeValue(value);
    }

    @Override
    public void writeValue(String value) {
        write(value);
    }

    @Override
    public void writeValue(int value) {
        write(Integer.toString(value));
    }

    @Override
    public void writeValue(long value) {
        write(Long.toString(value));
    }

    @Override
    public void writeValue(float value) {
        write(Float.toString(value));
    }

    @Override
    public void writeValue(double value) {
        write(Double.toString(value));
    }

    @Override
    public void writeValue(boolean value) {
        if (value) {
            osBuffer[index++] = 't';
            osBuffer[index++] = 'r';
            osBuffer[index++] = 'u';
            osBuffer[index++] = 'e';
        } else {
            osBuffer[index++] = 'f';
            osBuffer[index++] = 'a';
            osBuffer[index++] = 'l';
            osBuffer[index++] = 's';
            osBuffer[index++] = 'e';
        }
    }

    @Override
    public void writeValue(JsonValue value) {
        value.toJson(this);
    }

    @Override
    public void writeComma() {
        osBuffer[index++] = COMMA;
    }

    @Override
    public void writeColon() {
        osBuffer[index++] = COLON;
    }

    @Override
    public void writeNull() {
        osBuffer[index++] = 'n';
        osBuffer[index++] = 'u';
        osBuffer[index++] = 'l';
        osBuffer[index++] = 'l';
    }

    @Override
    public void writeArrayStart() {
        osBuffer[index++] = ARRAY_START;
    }

    @Override
    public void writeArrayEnd() {
        osBuffer[index++] = ARRAY_END;
    }

    @Override
    public void writeObjectStart() {
        osBuffer[index++] = OBJECT_START;
    }

    @Override
    public void writeObjectEnd() {
        osBuffer[index++] = OBJECT_END;
    }

    @Override
    public void writeQuoted(String value) {
        osBuffer[index++] = QUOTES;
        write(value);
        osBuffer[index++] = QUOTES;
    }

    private void write(String value) {
        byte[] bytes = value.getBytes();
        System.arraycopy(bytes, 0, osBuffer, index, bytes.length);
        index += bytes.length;
    }

    @Override
    public void close() throws Exception {
        outputStream.write(osBuffer, 0, index);
        outputStream.flush();
    }

}
