package io.helidon.json.processor;

import java.io.InputStream;

public sealed interface ReusableJsonParser extends JsonParser permits JsonParserImpl {

    void reset(byte[] buffer);

    void reset(byte[] buffer, int start);

    default void reset(InputStream is) {
        throw new UnsupportedOperationException("This is not supported reset operation");
    }

}
