package io.helidon.json.processor;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

class GeneratorOutputStream extends AbstractGenerator {

    private final static byte[] HEX_DIGITS = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    private final OutputStream outputStream;
    private final byte[] buffer = new byte[5120];
    private final byte[] digits = new byte[20];
    private int index = 0;
    private boolean closed;

    GeneratorOutputStream(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    @Override
    void ensureCapacity(int extra) {
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
            throw new JsonException("Stream write failed", e);
        }
    }

    @Override
    void writeString(String value) {
        ensureCapacity(1);
        buffer[index++] = QUOTES;
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
                ensureCapacity(1);
                buffer[index++] = (byte) c;
            } else if (c < 0x800) {
                ensureCapacity(2);
                buffer[index++] = (byte) (0b11000000 | (c >> 6));
                buffer[index++] = (byte) (0b10000000 | (c & 0x3F));
            } else if (Character.isHighSurrogate(c) || Character.isLowSurrogate(c)) {
                ensureCapacity(6);
                buffer[index++] = SLASH;
                buffer[index++] = 'u';
                buffer[index++] = HEX_DIGITS[(c >> 12) & 0xFF];
                buffer[index++] = HEX_DIGITS[(c >> 8) & 0xFF];
                buffer[index++] = HEX_DIGITS[(c >> 4) & 0xFF];
                buffer[index++] = HEX_DIGITS[c & 0xFF];
            } else {
                ensureCapacity(3);
                buffer[index++] = (byte) (0b11100000 | (c >> 12));
                buffer[index++] = (byte) (0b10000000 | ((c >> 6) & 0x3F));
                buffer[index++] = (byte) (0b10000000 | (c & 0x3F));
            }
        }
        ensureCapacity(1);
        buffer[index++] = QUOTES;
    }

    @Override
    void writeByte(byte value) {
        ensureCapacity(1);
        buffer[index++] = value;
    }

    @Override
    void writeLong(long value) {
        if (value == 0) {
            writeByte(ZERO);
        }
        long toProcess = value;
        int digits = 0;
        boolean negative = value < 0;
        if (negative) {
            ensureCapacity(1);
            buffer[index++] = MINUS;
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
    }

    @Override
    void writeFloat(float value) {
        //Performance improvement needed
        if (Float.isNaN(value) || Float.isInfinite(value)) {
            writeNull();
            return;
        } else if (value == 0.0) {
            buffer[index++] = (byte) '0';
            return;
        }

        // Convert to string (optimized native routine)
        String str = Float.toString(value);
        int len = str.length();

        ensureCapacity(len);
        for (int i = 0; i < len; i++) {
            buffer[index + i] = (byte) str.charAt(i); // ASCII digits + '.', 'E', '-', etc.
        }
        index += len;
    }

    @Override
    void writeDouble(double value) {
        //Performance improvement needed
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            writeNull();
            return;
        } else if (value == 0.0) {
            ensureCapacity(1);
            buffer[index++] = (byte) '0';
            return;
        }

        // Convert to string (optimized native routine)
        String str = Double.toString(value);
        int len = str.length();

        ensureCapacity(len);
        for (int i = 0; i < len; i++) {
            buffer[index + i] = (byte) str.charAt(i); // ASCII digits + '.', 'E', '-', etc.
        }
        index += len;
    }

    @Override
    void writeBoolean(boolean value) {
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
    }

    @Override
    void writeNullValue() {
        ensureCapacity(4);
        buffer[index++] = 'n';
        buffer[index++] = 'u';
        buffer[index++] = 'l';
        buffer[index++] = 'l';
    }

    @Override
    public void close() throws Exception {
        if (!closed) {
            closed = true;
            outputStream.write(buffer, 0, index);
            outputStream.flush();
            outputStream.close();
        }
    }

}
