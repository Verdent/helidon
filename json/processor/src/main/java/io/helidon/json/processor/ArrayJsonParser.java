package io.helidon.json.processor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TODO javadoc
 */
final class ArrayJsonParser extends AbstractJsonParser {

    ArrayJsonParser() {
        this(new byte[500]);
    }

    ArrayJsonParser(String json) {
        this(json.getBytes(StandardCharsets.UTF_8));
    }

    ArrayJsonParser(byte[] buffer) {
        this.buffer = buffer;
        this.bufferLength = buffer.length;
    }

    ArrayJsonParser(byte[] buffer, int start) {
        this.buffer = buffer;
        this.bufferLength = buffer.length;
        this.currentIndex = start;
    }

}
