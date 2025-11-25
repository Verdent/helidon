package io.helidon.json.processor;

import java.io.InputStream;

public interface ReusableJsonParser extends JsonParser {

    default void reset(byte[] buffer) {
        throw new UnsupportedOperationException("This is not supported reset operation");
    }

    default void reset(byte[] buffer, int start) {
        throw new UnsupportedOperationException("This is not supported reset operation");
    }

    default void reset(InputStream is) {
        throw new UnsupportedOperationException("This is not supported reset operation");
    }

}
