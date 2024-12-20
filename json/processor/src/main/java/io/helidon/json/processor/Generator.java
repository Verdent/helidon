package io.helidon.json.processor;

import java.io.OutputStream;

public interface Generator extends AutoCloseable {

    static Generator create(OutputStream outputStream) {
        return new GeneratorImpl(outputStream);
    }

    void writeKey(String key);

    void write(String key, String value);

    void write(String key, int value);

    void writeValue(String value);

    void writeValue(int value);

    void writeComma();

    void writeColon();
    void writeNull();

    void writeArrayStart();

    void writeArrayEnd();

    void writeObjectStart();

    void writeObjectEnd();

    void writeQuoted(String value);
}
