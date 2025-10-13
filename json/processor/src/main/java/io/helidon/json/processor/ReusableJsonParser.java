package io.helidon.json.processor;

import java.io.InputStream;

public sealed interface ReusableJsonParser extends JsonParser permits JsonParserImpl {

    void reset(byte[] buffer);

    default void reset(InputStream is) {
        throw new UnsupportedOperationException("This is not supported reset operation");
    }

}
