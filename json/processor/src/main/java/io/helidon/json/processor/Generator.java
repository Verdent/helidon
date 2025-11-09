package io.helidon.json.processor;

import java.io.OutputStream;

public interface Generator extends AutoCloseable {

    /**
     * Create a {@link Generator} implementation to write to the provided {@link OutputStream}.
     *
     * @param outputStream output stream to write to
     * @return new Generator instance
     */
    static Generator create(OutputStream outputStream) {
        return new GeneratorImpl(outputStream);
    }

    /**
     * Write a key value to the outstream.
     * Each key will be automatically enclosed with the quotes and colon appended {@code "key":}.
     *
     * @param key key value to write
     */
    void writeKey(String key);

    void write(String key, String value);

    void write(String key, int value);

    void write(String key, long value);

    void write(String key, float value);

    void write(String key, double value);

    void write(String key, boolean value);

    void write(String key, JsonObject value);

    void write(String value);

    void write(byte value);

    void write(short value);

    void write(int value);

    void write(long value);

    void write(float value);

    void write(double value);

    void write(boolean value);

    void write(JsonValue value);

    void writeComma();

    void writeColon();

    void writeNull();

    void writeArrayStart();

    void writeArrayEnd();

    void writeObjectStart();

    void writeObjectEnd();

    void writeQuoted(String value);
}
