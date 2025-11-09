package io.helidon.json.processor;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class GeneratorImpl implements Generator {

    private static final int STACK_SIZE = 64;

    private static final byte QUOTES = '"';
    private static final byte COMMA = ',';
    private static final byte COLON = ':';
    private static final byte ARRAY_START = '[';
    private static final byte ARRAY_END = ']';
    private static final byte OBJECT_START = '{';
    private static final byte OBJECT_END = '}';
    private static final byte SLASH = '\\';
    private static final byte ZERO = '0';
    private static final byte MINUS = '-';

    private final static byte[] HEX_DIGITS = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    private final OutputStream outputStream;
    private final byte[] buffer = new byte[5120];
    // stack structure tracking: true = object, false = array
    private boolean[] stackType = new boolean[STACK_SIZE];
    private boolean[] stackFirst = new boolean[STACK_SIZE];
    private byte[] digits = new byte[20];
    private int depth = 0;
    private int index = 0;
    private boolean failed = false;

    GeneratorImpl(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    private void ensureCapacity(int extra) {
        if (index + extra >= buffer.length) {
            flushBuffer();
        }
    }

    private void flushBuffer() {
        if (index == 0) {
            return;
        }
        try {
            outputStream.write(buffer, 0, index);
            index = 0;
        } catch (IOException e) {
            failed = true;
            throw new JsonException("Stream write failed", e);
        }
    }

    private void beforeValue() {
        //        if (depth > 0) {
        //            if (!stackFirst[depth - 1]) {
        //                writeByte(',');
        //            }
        //            if (depth > 0) stackFirst[depth - 1] = false;
        //        }
    }

    @Override
    public Generator writeKey(String key) {
        writeQuoted(key);
        writeColon();
        return this;
    }

    @Override
    public Generator write(String key, String value) {
        writeQuoted(key);
        writeColon();
        writeQuoted(value);
        return this;
    }

    @Override
    public Generator write(String key, int value) {
        writeQuoted(key);
        writeColon();
        write(value);
        return this;
    }

    @Override
    public Generator write(String key, long value) {
        writeQuoted(key);
        writeColon();
        write(value);
        return this;
    }

    @Override
    public Generator write(String key, float value) {
        writeQuoted(key);
        writeColon();
        write(value);
        return this;
    }

    @Override
    public Generator write(String key, double value) {
        writeQuoted(key);
        writeColon();
        write(value);
        return this;
    }

    @Override
    public Generator write(String key, boolean value) {
        writeQuoted(key);
        writeColon();
        write(value);
        return this;
    }

    @Override
    public Generator write(String key, JsonObject value) {
        writeQuoted(key);
        writeColon();
        write(value);
        return this;
    }

    @Override
    public Generator write(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20) {
                //Non-printable character
                if (c == '\n' || c == '\r' || c == '\t' || c == '\b' || c == '\f') {
                    ensureCapacity(2);
                    buffer[index++] = SLASH;
                    buffer[index++] = (byte) c;
                } else {
                    ensureCapacity(6);
                    buffer[index++] = SLASH;
                    buffer[index++] = 'u';
                    buffer[index++] = '0';
                    buffer[index++] = '0';
                    buffer[index++] = HEX_DIGITS[(c >> 4) & 0xF];
                    buffer[index++] = HEX_DIGITS[c & 0xF];
                }
            } else if (c == '"' || c == '\\') {
                ensureCapacity(2);
                buffer[index++] = SLASH;
                buffer[index++] = (byte) c;
            } else if (c < 0x80) {
                //Character is an ASCII char. No multibyte handling required.
                write((byte) c);
            } else if (c < 0x800) {
                ensureCapacity(2);
                buffer[index++] = (byte) (0b11000000 | (c >> 6));
                buffer[index++] = (byte) (0b10000000 | (c & 0b00111111));
            } else if (Character.isHighSurrogate(c) || Character.isLowSurrogate(c)) {
                ensureCapacity(6);
                buffer[index++] = SLASH;
                buffer[index++] = 'u';
                buffer[index++] = HEX_DIGITS[(c >> 12) & 0xF];
                buffer[index++] = HEX_DIGITS[(c >> 8) & 0xF];
                buffer[index++] = HEX_DIGITS[(c >> 4) & 0xF];
                buffer[index++] = HEX_DIGITS[c & 0xF];
            } else {
                ensureCapacity(3);
                buffer[index++] = (byte) (0b11100000 | (c >> 12));
                buffer[index++] = (byte) (0b10000000 | ((c >> 6) & 0b00111111));
                buffer[index++] = (byte) (0b10000000 | (c & 0b00111111));
            }
        }
        return this;
    }

    @Override
    public Generator write(byte value) {
        ensureCapacity(1);
        buffer[index++] = value;
        return this;
    }

    @Override
    public Generator write(short value) {
        write((int) value);
        return this;
    }

    @Override
    public Generator write(int value) {
        if (value == 0) {
            return write(ZERO);
        }
        int toProcess = value;
        int digits = 0;
        boolean negative = value < 0;
        if (negative) {
            write(MINUS);
            toProcess = -toProcess;
        }
        while (toProcess > 0) {
            this.digits[digits++] = (byte) ('0' + toProcess % 10);
            toProcess /= 10;
        }
        ensureCapacity(digits);
        for (int i = --digits; i >= 0; i--) {
            buffer[index++] = this.digits[i];
        }
        return this;
    }

    @Override
    public Generator write(long value) {
        if (value == 0) {
            return write(ZERO);
        }
        long toProcess = value;
        int digits = 0;
        boolean negative = value < 0;
        if (negative) {
            write(MINUS);
            toProcess = -toProcess;
        }
        while (toProcess > 0) {
            this.digits[digits++] = (byte) ('0' + toProcess % 10);
            toProcess /= 10;
        }
        ensureCapacity(digits);
        for (int i = --digits; i >= 0; i--) {
            buffer[index++] = this.digits[i];
        }
        return this;
    }

    @Override
    public Generator write(float value) {
        return write(Float.toString(value));
    }

    @Override
    public Generator write(double value) {
        return write(Double.toString(value));
    }

    @Override
    public Generator write(boolean value) {
        if (value) {
            ensureCapacity(4);
            buffer[index++] = 't';
            buffer[index++] = 'r';
            buffer[index++] = 'u';
            buffer[index++] = 'e';
        } else {
            ensureCapacity(5);
            buffer[index++] = 'f';
            buffer[index++] = 'a';
            buffer[index++] = 'l';
            buffer[index++] = 's';
            buffer[index++] = 'e';
        }
        return this;
    }

    @Override
    public Generator write(JsonValue value) {
        value.toJson(this);
        return this;
    }

    @Override
    public void writeComma() {
        ensureCapacity(1);
        buffer[index++] = COMMA;
    }

    @Override
    public void writeColon() {
        ensureCapacity(1);
        buffer[index++] = COLON;
    }

    @Override
    public Generator writeNull() {
        ensureCapacity(4);
        buffer[index++] = 'n';
        buffer[index++] = 'u';
        buffer[index++] = 'l';
        buffer[index++] = 'l';
        return this;
    }

    @Override
    public Generator writeArrayStart() {
        ensureCapacity(1);
        buffer[index++] = ARRAY_START;
        return this;
    }

    @Override
    public Generator writeArrayEnd() {
        buffer[index++] = ARRAY_END;
        return this;
    }

    @Override
    public Generator writeObjectStart() {
        ensureCapacity(1);
        buffer[index++] = OBJECT_START;
        return this;
    }

    @Override
    public Generator writeObjectEnd() {
        ensureCapacity(1);
        buffer[index++] = OBJECT_END;
        return this;
    }

    @Override
    public void writeQuoted(String value) {
        ensureCapacity(1);
        buffer[index++] = QUOTES;
        write(value);
        ensureCapacity(1);
        buffer[index++] = QUOTES;
    }

    private void writeValue(String value) {
        byte[] bytes = value.getBytes();
        System.arraycopy(bytes, 0, buffer, index, bytes.length);
        index += bytes.length;
    }

    @Override
    public void close() throws Exception {
        outputStream.write(buffer, 0, index);
        outputStream.flush();
    }

}
