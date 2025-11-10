package io.helidon.json.processor;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

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
    private final byte[] digits = new byte[20];
    // stack structure tracking: true = object, false = array
    private boolean[] structureType = new boolean[STACK_SIZE];
    private boolean first = true;
    private boolean keyWritten = false;
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

    private void beforeWrite() {
        if (depth > 0) {
            if (first) {
                first = false;
            } else if (keyWritten) {
                keyWritten = false;
            } else {
                ensureCapacity(1);
                buffer[index++] = COMMA;
            }
        } else if (first) {
            first = false;
        } else {
            throw new JsonException("Multiple values not supported as a root value.");
        }
    }

    @Override
    public Generator writeKey(String key) {
        if (depth == 0 || !structureType[depth - 1]) {
            throw new JsonException("Key can be written only into the object.");
        } else if (keyWritten) {
            throw new JsonException("Cannot write key twice.");
        }
        beforeWrite();
        writeString(key);
        writeColon();
        keyWritten = true;
        return this;
    }

    @Override
    public Generator write(String key, String value) {
        if (depth == 0 || !structureType[depth - 1]) {
            throw new JsonException("Key can be written only into the object.");
        } else if (keyWritten) {
            throw new JsonException("Cannot write key twice.");
        }
        beforeWrite();
        writeString(key);
        writeColon();
        writeString(value);
        return this;
    }

    @Override
    public Generator write(String key, int value) {
        if (depth == 0 || !structureType[depth - 1]) {
            throw new JsonException("Key can be written only into the object.");
        } else if (keyWritten) {
            throw new JsonException("Cannot write key twice.");
        }
        beforeWrite();
        writeString(key);
        writeColon();
        return writeLong(value);
    }

    @Override
    public Generator write(String key, long value) {
        if (depth == 0 || !structureType[depth - 1]) {
            throw new JsonException("Key can be written only into the object.");
        } else if (keyWritten) {
            throw new JsonException("Cannot write key twice.");
        }
        beforeWrite();
        writeString(key);
        writeColon();
        return writeLong(value);
    }

    @Override
    public Generator write(String key, float value) {
        if (depth == 0 || !structureType[depth - 1]) {
            throw new JsonException("Key can be written only into the object.");
        } else if (keyWritten) {
            throw new JsonException("Cannot write key twice.");
        }
        beforeWrite();
        writeString(key);
        writeColon();
        writeDouble(value);
        return this;
    }

    @Override
    public Generator write(String key, double value) {
        if (depth == 0 || !structureType[depth - 1]) {
            throw new JsonException("Key can be written only into the object.");
        } else if (keyWritten) {
            throw new JsonException("Cannot write key twice.");
        }
        beforeWrite();
        writeString(key);
        writeColon();
        writeDouble(value);
        return this;
    }

    @Override
    public Generator write(String key, boolean value) {
        if (depth == 0 || !structureType[depth - 1]) {
            throw new JsonException("Key can be written only into the object.");
        } else if (keyWritten) {
            throw new JsonException("Cannot write key twice.");
        }
        beforeWrite();
        writeString(key);
        writeColon();
        writeBoolean(value);
        return this;
    }

    @Override
    public Generator write(String key, JsonValue value) {
        if (depth == 0 || !structureType[depth - 1]) {
            throw new JsonException("Key can be written only into the object.");
        } else if (keyWritten) {
            throw new JsonException("Cannot write key twice.");
        }
        beforeWrite();
        writeString(key);
        writeColon();
        writeJsonValue(value);
        return this;
    }

    @Override
    public Generator write(String value) {
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        writeString(value);
        return this;
    }

    private void writeString(String value) {
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
        ensureCapacity(1);
        buffer[index++] = QUOTES;
    }

    @Override
    public Generator write(byte value) {
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        ensureCapacity(1);
        buffer[index++] = value;
        return this;
    }

    @Override
    public Generator write(short value) {
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        return writeLong(value);
    }

    @Override
    public Generator write(int value) {
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        return writeLong(value);
    }

    @Override
    public Generator write(long value) {
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        return writeLong(value);
    }

    private Generator writeLong(long value) {
        if (value == 0) {
            return write(ZERO);
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
        return this;
    }

    @Override
    public Generator write(float value) {
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        writeDouble(value);
        return this;
    }

    @Override
    public Generator write(double value) {
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        writeDouble(value);
        return this;
    }

    private void writeDouble(double value) {
        throw new JsonException("Not implemented yet");
    }

    @Override
    public Generator write(boolean value) {
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        writeBoolean(value);
        return this;
    }

    private void writeBoolean(boolean value) {
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
    public Generator write(JsonValue value) {
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        writeJsonValue(value);
        return this;
    }

    private void writeJsonValue(JsonValue value) {
        value.toJson(this);
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
        if (depth > 0 && structureType[depth - 1] && !keyWritten) {
            throw new JsonException("Value without key is supported only as a root or in the array.");
        }
        beforeWrite();
        ensureCapacity(4);
        buffer[index++] = 'n';
        buffer[index++] = 'u';
        buffer[index++] = 'l';
        buffer[index++] = 'l';
        return this;
    }

    @Override
    public Generator writeArrayStart() {
        if (!keyWritten) {
            beforeWrite();
        } else {
            keyWritten = false;
        }
        pushStructureType(false);
        ensureCapacity(1);
        buffer[index++] = ARRAY_START;
        return this;
    }

    @Override
    public Generator writeArrayEnd() {
        popStackType();
        ensureCapacity(1);
        buffer[index++] = ARRAY_END;
        first = false;
        return this;
    }

    @Override
    public Generator writeObjectStart() {
        if (!keyWritten) {
            beforeWrite();
        } else {
            keyWritten = false;
        }
        ensureCapacity(1);
        buffer[index++] = OBJECT_START;
        pushStructureType(true);
        return this;
    }

    @Override
    public Generator writeObjectEnd() {
        popStackType();
        ensureCapacity(1);
        buffer[index++] = OBJECT_END;
        first = false;
        return this;
    }

    @Override
    public void close() throws Exception {
        outputStream.write(buffer, 0, index);
        outputStream.flush();
    }

    private void pushStructureType(boolean isObject) {
        if (depth >= STACK_SIZE) {
            throw new IllegalStateException("Nesting too deep");
        }
        structureType[depth] = isObject;
        first = true;
        depth++;
    }

    private void popStackType() {
        depth--;
        if (depth < 0) {
            throw new IllegalStateException("Invalid JSON structure");
        }
    }

}
