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
    Generator writeKey(String key);

    Generator write(String key, String value);

    Generator write(String key, int value);

    Generator write(String key, long value);

    Generator write(String key, float value);

    Generator write(String key, double value);

    Generator write(String key, boolean value);

    Generator write(String key, JsonValue value);

    Generator write(String value);

    Generator write(byte value);

    Generator write(short value);

    Generator write(int value);

    Generator write(long value);

    Generator write(float value);

    Generator write(double value);

    Generator write(boolean value);

    Generator write(JsonValue value);

    void writeComma();

    void writeColon();

    Generator writeNull();

    Generator writeArrayStart();

    Generator writeArrayEnd();

    Generator writeObjectStart();

    Generator writeObjectEnd();
}
