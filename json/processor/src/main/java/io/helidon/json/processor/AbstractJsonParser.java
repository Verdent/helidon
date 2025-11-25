package io.helidon.json.processor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

abstract class AbstractJsonParser implements ReusableJsonParser  {

    static final int FNV_OFFSET_BASIS = 0x811c9dc5;
    static final int FNV_PRIME = 0x01000193;

    //We need this to check if the next number digit overflows int max capacity
    static final byte BYTE_SIZE_BORDER = Byte.MAX_VALUE / 10;
    static final short SHORT_SIZE_BORDER = Short.MAX_VALUE / 10;
    static final int INT_SIZE_BORDER = Integer.MAX_VALUE / 10;
    static final long LONG_SIZE_BORDER = Long.MAX_VALUE / 10;

    static final int[] WHOLE_NUMBER_PARTS = new int[256];

    static final double[] POW_DOUBLE_CACHE = new double[] {
            1,
            10,
            100,
            1000,
            10000,
            100000,
            1000000,
            10000000,
            100000000,
            1000000000,
            10000000000L,
            100000000000L,
            1000000000000L,
            10000000000000L,
            100000000000000L,
            1000000000000000L,
            10000000000000000L,
            100000000000000000L,
            1000000000000000000L,
    };
    static final float[] POW_FLOAT_CACHE = new float[] {
            1,
            10,
            100,
            1000,
            10000,
            100000,
            1000000,
            10000000,
            100000000,
            1000000000,
            10000000000L,
            100000000000L,
            1000000000000L,
            10000000000000L,
            100000000000000L,
            1000000000000000L,
            10000000000000000L,
            100000000000000000L,
            1000000000000000000L,
    };

    static {
        Arrays.fill(WHOLE_NUMBER_PARTS, -1);

        for (int i = '0'; i <= '9'; ++i) {
            WHOLE_NUMBER_PARTS[i] = (i - '0') & 0xFF;
        }
    }

    static final boolean[] WHITESPACE_CHARS = new boolean[256];

    static {
        // ASCII whitespace
        WHITESPACE_CHARS[0x09 & 0xFF] = true; // TAB
        WHITESPACE_CHARS[0x0A & 0xFF] = true; // LF
        WHITESPACE_CHARS[0x0B & 0xFF] = true; // VT
        WHITESPACE_CHARS[0x0C & 0xFF] = true; // FF
        WHITESPACE_CHARS[0x0D & 0xFF] = true; // CR
        WHITESPACE_CHARS[0x20 & 0xFF] = true; // SPACE
    }

    final static int[] HEX_DIGITS = new int['f' + 1];

    static {
        Arrays.fill(HEX_DIGITS, -1);
        for (int i = '0'; i <= '9'; ++i) {
            HEX_DIGITS[i] = (i - '0');
        }
        for (int i = 'a'; i <= 'f'; ++i) {
            HEX_DIGITS[i] = ((i - 'a') + 10);
        }
        for (int i = 'A'; i <= 'F'; ++i) {
            HEX_DIGITS[i] = ((i - 'A') + 10);
        }
    }

    int stringBufferLength = 64;
    char[] stringBuffer = new char[stringBufferLength];
    boolean expectLowSurrogate = false;

    byte[] buffer;
    int currentIndex = -1;
    int bufferLength;

    AbstractJsonParser() {
        this(new byte[500]);
    }

    AbstractJsonParser(byte[] buffer) {
        this.buffer = buffer;
        this.bufferLength = buffer.length;
    }

    @Override
    public void reset(byte[] buffer) {
        this.buffer = buffer;
        this.bufferLength = buffer.length;
        this.currentIndex = -1;
    }

    @Override
    public void reset(byte[] buffer, int start) {
        this.buffer = buffer;
        this.bufferLength = buffer.length;
        this.currentIndex = start;
    }

    @Override
    public byte currentByte() {
        return buffer[currentIndex];
    }

    @Override
    public byte nextToken() {
        //Optimization for faster reading data without a space
        //No loop is used.
        byte b;
        if (++currentIndex == bufferLength) {
            throw new JsonException("Incomplete JSON.");
        }
        b = buffer[currentIndex];
        if (!WHITESPACE_CHARS[b & 0xFF]) {
            return b;
        }
        //If since space or why character was used between tokens, we should still try to optimize
        if (++currentIndex == bufferLength) {
            throw new JsonException("Incomplete JSON.");
        }
        b = buffer[currentIndex];
        if (!WHITESPACE_CHARS[b & 0xFF]) {
            return b;
        }
        //We dont know how many spaces, new lines etc is there present, lets start looping
        for (int i = currentIndex + 1; i < bufferLength; i++) {
            b = buffer[i];
            if (!WHITESPACE_CHARS[b & 0xFF]) {
                currentIndex = i;
                return b;
            }
        }
        throw new JsonException("Json incomplete!");
    }

    @Override
    public boolean hasNext() {
        return currentIndex + 1 < bufferLength;
    }

    byte readNextByte() {
        return buffer[++currentIndex];
    }

    @Override
    public JsonValue readJsonValue() {
        byte b = currentIndex == -1 ? nextToken() : currentByte();
        switch (b) {
        case '{':
            return readJsonObject();
        case '[':
            return readJsonArray();
        case '"':
            return readJsonString();
        case '-':
        case '.':
        case '+':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return readJsonNumber();
        case 't':
        case 'f':
            return JsonBoolean.create(readAsBoolean());
        case 'n':
            checkNull();
            return JsonNull.instance();
        default:
            throw new JsonException("Unsupported yet!");
        }
    }

    @Override
    public JsonObject readJsonObject() {
        if (currentByte() != '{') {
            throw new JsonException("Object start expected at index: " + realIndex() + ", but was: " + (char) currentByte());
        }
        byte b = nextToken();
        if (b == '}') {
            return JsonObject.EMPTY_OBJECT;
        }
        List<JsonObject.Pair> pairs = new ArrayList<>();
        while (hasNext()) {
            JsonString key;
            if (b == '"') {
                key = readJsonString();
            } else {
                throw new JsonException("Key name expected at index: " + realIndex() + ", but was: " + Character.toString(b));
            }
            b = nextToken();
            if (b != ':') {
                throw new JsonException("Colon expected at index: " + realIndex() + ", but was: " + Character.toString(b));
            }
            b = nextToken();
            switch (b) {
            case '"':
                pairs.add(new JsonObject.Pair(key, readJsonString()));
                break;
            case '{':
                pairs.add(new JsonObject.Pair(key, readJsonObject()));
                break;
            case '[':
                pairs.add(new JsonObject.Pair(key, readJsonArray()));
                break;
            case '-':
            case '.':
            case '+':
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                pairs.add(new JsonObject.Pair(key, readJsonNumber()));
                break;
            case 'n':
                checkNull();
                pairs.add(new JsonObject.Pair(key, JsonNull.instance()));
                break;
            case 't':
            case 'f':
                pairs.add(new JsonObject.Pair(key, JsonBoolean.create(readAsBoolean())));
                break;
            default:
                throw new JsonException("Unexpected token at index: " + realIndex());
            }
            b = nextToken();
            if (b == '}') {
                return JsonObject.create(pairs);
            } else if (b != ',') {
                throw new JsonException("Comma or } expected at index: " + realIndex() + ", but was: " + (char) b);
            }
            b = nextToken();
        }
        throw new JsonException("Unexpected end of the object at index: " + realIndex() + ", but was: " + (char) b);
    }

    @Override
    public JsonArray readJsonArray() {
        byte b = nextToken();
        if (b == ']') {
            return JsonArray.EMPTY_ARRAY;
        }
        List<JsonValue> values = new ArrayList<>();
        while (hasNext()) {
            switch (b) {
            case '"':
                values.add(readJsonString());
                break;
            case '{':
                values.add(readJsonObject());
                break;
            case '[':
                values.add(readJsonArray());
                break;
            case '-':
            case '.':
            case '+':
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                values.add(readJsonNumber());
                break;
            case 'n':
                checkNull();
                values.add(JsonNull.instance());
                break;
            case 't':
            case 'f':
                values.add(JsonBoolean.create(readAsBoolean()));
                break;
            default:
                throw new JsonException("Invalid array value token at index: " + realIndex());
            }
            b = nextToken();
            if (b == ']') {
                return JsonArray.create(values);
            } else if (b != ',') {
                throw new JsonException("Comma or ] expected at index: " + realIndex() + ", but was: " + (char) b);
            }
            b = nextToken();
        }
        throw new JsonException("Unexpected end of the object at index: " + realIndex() + ", but was: " + (char) b);
    }

    @Override
    public JsonString readJsonString() {
        int start = currentIndex + 1;
        skipStringValue();
        int length = currentIndex - start;
        return JsonString.create(buffer, start, length);
    }

    @Override
    public JsonNumber readJsonNumber() {
        int start = currentIndex;
        skipNumber();
        return JsonNumber.create(buffer, start, currentIndex - start);
    }

    int realIndex() {
        return currentIndex - 1;
    }

    @Override
    public String readString() {
        if (checkNull()) {
            return null;
        } else if (currentByte() != '\"') {
            throw new JsonException("Start of a string expected, but found: " + (char) currentByte());
        }
        int firstRun = stringBufferLength > bufferLength - currentIndex ? bufferLength : stringBufferLength;
        int stringBuffIndex = 0;
        byte b;
        for ( ; stringBuffIndex < firstRun; stringBuffIndex++) {
            b = this.buffer[++currentIndex];
            if (b == '"') {
                return new String(stringBuffer, 0, stringBuffIndex);
            }
            if (b == '\\' || b < 0) {
                //Specialized character handling is likely required
                //Either escaped sequence or multibyte detected
                currentIndex--;
                break;
            }
            stringBuffer[stringBuffIndex] = (char) b;
        }

        if (stringBuffIndex == stringBufferLength) {
            increaseStringBuffer();
        }

        while (currentIndex + 1 < this.bufferLength) {
            b = readNextByte();
            if (b == '\\') {
                stringBuffer[stringBuffIndex++] = processEscapedSequence();
            } else if (b == '"') {
                return new String(stringBuffer, 0, stringBuffIndex);
            } else if ((b & 0x80) == 0) {
                stringBuffer[stringBuffIndex++] = (char) b;
            } else {
                stringBuffIndex = decodeUtf8(stringBuffIndex, b);
            }
            if (stringBuffIndex == stringBufferLength) {
                increaseStringBuffer();
            }
        }
        throw new JsonException("Incomplete JSON");
    }

    private char processEscapedSequence() {
        if (!hasNext()) {
            throw new JsonException("Incomplete JSON.");
        }
        byte c = buffer[++currentIndex];
        switch (c) {
        case '\\':
        case '"':
        case '/':
            return (char) c;
        case 'b':
            return '\b';
        case 't':
            return '\t';
        case 'n':
            return '\n';
        case 'f':
            return '\f';
        case 'r':
            return '\r';
        case 'u':
            ensure(4);
            char tmp = (char) (
                    (translateHex(buffer[++currentIndex]) << 12) +
                            (translateHex(buffer[++currentIndex]) << 8) +
                            (translateHex(buffer[++currentIndex]) << 4) +
                            translateHex(buffer[++currentIndex]));
            if (Character.isHighSurrogate(tmp)) {
                if (expectLowSurrogate) {
                    throw new JsonException("High surrogate is always required to be followed by the low surrogate");
                } else {
                    expectLowSurrogate = true;
                }
            } else if (Character.isLowSurrogate(tmp)) {
                if (expectLowSurrogate) {
                    expectLowSurrogate = false;
                } else {
                    throw new JsonException("Low surrogate is always required to be after the high surrogate");
                }
            } else if (expectLowSurrogate) {
                throw new JsonException("Low surrogate was expected to follow the high surrogate, but was '" + tmp + "'");
            }
            return tmp;
        default:
            throw new JsonException("Invalid escaped character: " + c);
        }
    }

    private int decodeUtf8(int position, byte currentByte) {
        if ((currentByte & 0xE0) == 0xC0) {
            int c2 = readNextByte() & 0x3F;
            int codePoint = ((currentByte & 0x1F) << 6) | c2;
            stringBuffer[position++] = (char) codePoint;
        } else if ((currentByte & 0xF0) == 0xE0) {
            ensure(2);
            int c2 = buffer[++currentIndex] & 0x3F;
            int c3 = buffer[++currentIndex] & 0x3F;
            int codePoint = ((currentByte & 0x0F) << 12) | (c2 << 6) | c3;
            stringBuffer[position++] = (char) codePoint;
        } else if ((currentByte & 0xF8) == 0xF0) {
            ensure(3);
            int c2 = buffer[++currentIndex] & 0x3F;
            int c3 = buffer[++currentIndex] & 0x3F;
            int c4 = buffer[++currentIndex] & 0x3F;
            int codePoint = ((currentByte & 0x07) << 18) | (c2 << 12) | (c3 << 6) | c4;
            if (codePoint >= 0x10000) {
                if (codePoint >= 0x110000) {
                    throw new JsonException("Invalid UTF-8 code point: " + Integer.toHexString(codePoint));
                }
                codePoint -= 0x10000;
                stringBuffer[position++] = (char) ((codePoint >> 10) + 0xD800); //High surrogate
                if (position == stringBufferLength) {
                    increaseStringBuffer();
                }
                stringBuffer[position++] = (char) ((codePoint & 0x3FF) + 0xDC00); //Low surrogate
            } else {
                stringBuffer[position++] = (char) codePoint;
            }
        } else {
            throw new JsonException("Invalid UTF-8 byte: " + currentByte);
        }
        return position;
    }

    private void increaseStringBuffer() {
        stringBufferLength *= 2;
        char[] newBuf = new char[stringBufferLength];
        System.arraycopy(stringBuffer, 0, newBuf, 0, stringBuffer.length);
        stringBuffer = newBuf;
    }

    @Override
    public char[] readNumberAsArray() {
        int i = 0;
        stringBuffer[i++] = (char) buffer[currentIndex];
        while (true) {
            byte c = readNextByte();
            switch (c) {
            case 'e', 'E', '.', '-', '+', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
                stringBuffer[i++] = (char) c;
                break;
            default:
                --currentIndex;
                char[] numberBuffer = new char[i];
                System.arraycopy(stringBuffer, 0, numberBuffer, 0, i);
                return numberBuffer;
            }
            if (i == stringBufferLength) {
                increaseStringBuffer();
            }
        }
    }

    @Override
    public boolean readAsBoolean() {
        switch (currentByte()) {
        case 't':
            ensure(3);
            if (buffer[++currentIndex] == 'r'
                    && buffer[++currentIndex] == 'u'
                    && buffer[++currentIndex] == 'e') {
                return true;
            }
            throw new JsonException("Expected value true at index: " + (currentIndex - 3));
        case 'f':
            ensure(4);
            if (buffer[++currentIndex] == 'a'
                    && buffer[++currentIndex] == 'l'
                    && buffer[++currentIndex] == 's'
                    && buffer[++currentIndex] == 'e') {
                return false;
            }
            throw new JsonException("Expected value false at index: " + (currentIndex - 4));
        default:
            throw new JsonException("Expected boolean value at index: " + currentIndex);
        }
    }

    @Override
    public byte readAsByte() {
        if (currentByte() == '-') {
            currentIndex = currentIndex + 1;
            return (byte) -parseByte(true);
        } else {
            return parseByte(false);
        }
    }

    private byte parseByte(boolean negative) {
        int digit1 = WHOLE_NUMBER_PARTS[currentByte() & 0xFF];
        if (digit1 == -1) {
            throw new JsonException("Expected number, but was: " + (char) currentByte());
        }
        boolean hasNext = hasNext();
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit2 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (byte) digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        int possibleResult = digit1 * 10 + digit2;
        if (digit3 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (byte) possibleResult;
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit4 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            if (negative) {
                if (-possibleResult > -BYTE_SIZE_BORDER || (-possibleResult == -BYTE_SIZE_BORDER && digit3 <= 8)) {
                    return (byte) (possibleResult * 10 + digit3);
                }
            } else if (possibleResult < BYTE_SIZE_BORDER || (possibleResult == BYTE_SIZE_BORDER && digit3 <= 7)) {
                return (byte) (possibleResult * 10 + digit3);
            }
        }
        hasNext = hasNext();
        //The Number is too big. Lets read it all and report in the exception
        StringBuilder number = new StringBuilder();
        if (negative) {
            number.append("-");
        }
        number.append(possibleResult).append(digit3);
        if (digit4 != -1) {
            int digit = digit4;
            while (digit != -1) {
                number.append(digit);
                digit = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
                hasNext = hasNext();
            }
        }
        if (hasNext) {
            currentIndex--;
        }
        throw new JsonException("Number is too big for a byte value: " + number);
    }

    @Override
    public short readAsShort() {
        if (currentByte() == '-') {
            currentIndex = currentIndex + 1;
            return (short) -parseShort(true);
        } else {
            return parseShort(false);
        }
    }

    private short parseShort(boolean negative) {
        int digit1 = WHOLE_NUMBER_PARTS[currentByte() & 0xFF];
        if (digit1 == -1) {
            throw new JsonException("Expected number, but was: " + (char) currentByte());
        }
        if (currentIndex + 6 < bufferLength) {
            int digit2 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit2 == -1) {
                currentIndex--;
                return (short) digit1;
            }
            int digit3 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit3 == -1) {
                currentIndex--;
                return (short) (digit1 * 10 + digit2);
            }
            int digit4 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit4 == -1) {
                currentIndex--;
                return (short) (digit1 * 100 + digit2 * 10 + digit3);
            }
            int digit5 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            short possibleResult = (short) (digit1 * 1000 + digit2 * 100 + digit3 * 10 + digit4);
            if (digit5 == -1) {
                currentIndex--;
                return possibleResult;
            }
            int digit6 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit6 == -1) {
                currentIndex--;
                if (negative) {
                    if (-possibleResult > -SHORT_SIZE_BORDER || (-possibleResult == -SHORT_SIZE_BORDER && digit5 <= 8)) {
                        return (short) (possibleResult * 10 + digit5);
                    }
                } else if (possibleResult < SHORT_SIZE_BORDER || (possibleResult == SHORT_SIZE_BORDER && digit5 <= 7)) {
                    return (short) (possibleResult * 10 + digit5);
                }
            }
        }
        boolean hasNext = hasNext();
        int digit2 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit2 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (short) digit1;
        }
        hasNext = hasNext();
        int digit3 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit3 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (short) (digit1 * 10 + digit2);
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit4 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (short) (digit1 * 100 + digit2 * 10 + digit3);
        }
        hasNext = hasNext();
        int digit5 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        short possibleResult = (short) (digit1 * 1000 + digit2 * 100 + digit3 * 10 + digit4);
        if (digit5 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return possibleResult;
        }
        hasNext = hasNext();
        int digit6 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit6 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            if (negative) {
                if (-possibleResult > -SHORT_SIZE_BORDER || (-possibleResult == -SHORT_SIZE_BORDER && digit5 <= 8)) {
                    return (short) (possibleResult * 10 + digit5);
                }
            } else if (possibleResult < SHORT_SIZE_BORDER || (possibleResult == SHORT_SIZE_BORDER && digit5 <= 7)) {
                return (short) (possibleResult * 10 + digit5);
            }
        }
        hasNext = hasNext();
        //The Number is too big. Lets read it all and report in the exception
        StringBuilder number = new StringBuilder();
        if (negative) {
            number.append("-");
        }
        number.append(possibleResult).append(digit5);
        if (digit6 != -1) {
            int digit = digit6;
            while (digit != -1) {
                number.append(digit);
                digit = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
                hasNext = hasNext();
            }
        }
        if (hasNext) {
            currentIndex--;
        }
        throw new JsonException("Number is too big for a short value: " + number);
    }

    @Override
    public int readAsInt() {
        if (currentByte() == '-') {
            currentIndex++;
            return -parseInt(true);
        } else {
            return parseInt(false);
        }
    }

    private int parseInt(boolean negative) {
        if (currentIndex + 11 < bufferLength) {
            int digit1 = WHOLE_NUMBER_PARTS[currentByte() & 0xFF];
            if (digit1 == -1) {
                throw new JsonException("Expected number, but was: " + (char) currentByte());
            }
            int digit2 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit2 == -1) {
                currentIndex--;
                return digit1;
            }
            int digit3 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit3 == -1) {
                currentIndex--;
                return digit1 * 10 + digit2;
            }
            int digit4 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit4 == -1) {
                currentIndex--;
                return digit1 * 100
                        + digit2 * 10
                        + digit3;
            }
            int digit5 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit5 == -1) {
                currentIndex--;
                return digit1 * 1000
                        + digit2 * 100
                        + digit3 * 10
                        + digit4;
            }
            int digit6 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit6 == -1) {
                currentIndex--;
                return digit1 * 10000
                        + digit2 * 1000
                        + digit3 * 100
                        + digit4 * 10
                        + digit5;
            }
            int digit7 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit7 == -1) {
                currentIndex--;
                return digit1 * 100000
                        + digit2 * 10000
                        + digit3 * 1000
                        + digit4 * 100
                        + digit5 * 10
                        + digit6;
            }
            int digit8 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit8 == -1) {
                currentIndex--;
                return digit1 * 1000000
                        + digit2 * 100000
                        + digit3 * 10000
                        + digit4 * 1000
                        + digit5 * 100
                        + digit6 * 10
                        + digit7;
            }
            int digit9 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit9 == -1) {
                currentIndex--;
                return digit1 * 10000000
                        + digit2 * 1000000
                        + digit3 * 100000
                        + digit4 * 10000
                        + digit5 * 1000
                        + digit6 * 100
                        + digit7 * 10
                        + digit8;
            }
            int digit10 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            int possibleResult = digit1 * 100000000
                    + digit2 * 10000000
                    + digit3 * 1000000
                    + digit4 * 100000
                    + digit5 * 10000
                    + digit6 * 1000
                    + digit7 * 100
                    + digit8 * 10
                    + digit9;
            if (digit10 == -1) {
                currentIndex--;
                return possibleResult;
            }
            int digit11 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit11 == -1) {
                currentIndex--;
                if (negative) {
                    if (-possibleResult > -INT_SIZE_BORDER || (-possibleResult == -INT_SIZE_BORDER && digit10 <= 8)) {
                        return possibleResult * 10 + digit10;
                    }
                } else if (possibleResult < INT_SIZE_BORDER || (possibleResult == INT_SIZE_BORDER && digit10 <= 7)) {
                    return possibleResult * 10 + digit10;
                }
            }
            //TODO upravit na handling prilis dlouhych cisel
        }
        int digit1 = WHOLE_NUMBER_PARTS[currentByte()];
        if (digit1 == -1) {
            throw new JsonException("Expected number, but was: " + (char) currentByte());
        }
        boolean hasNext = hasNext();
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit2 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit3 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10 + digit2;
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit4 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100
                    + digit2 * 10
                    + digit3;
        }
        hasNext = hasNext();
        int digit5 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit5 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 1000
                    + digit2 * 100
                    + digit3 * 10
                    + digit4;
        }
        hasNext = hasNext();
        int digit6 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit6 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10000
                    + digit2 * 1000
                    + digit3 * 100
                    + digit4 * 10
                    + digit5;
        }
        hasNext = hasNext();
        int digit7 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit7 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100000
                    + digit2 * 10000
                    + digit3 * 1000
                    + digit4 * 100
                    + digit5 * 10
                    + digit6;
        }
        hasNext = hasNext();
        int digit8 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit8 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 1000000
                    + digit2 * 100000
                    + digit3 * 10000
                    + digit4 * 1000
                    + digit5 * 100
                    + digit6 * 10
                    + digit7;
        }
        hasNext = hasNext();
        int digit9 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit9 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10000000
                    + digit2 * 1000000
                    + digit3 * 100000
                    + digit4 * 10000
                    + digit5 * 1000
                    + digit6 * 100
                    + digit7 * 10
                    + digit8;
        }
        hasNext = hasNext();
        int digit10 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        int possibleResult = digit1 * 100000000
                + digit2 * 10000000
                + digit3 * 1000000
                + digit4 * 100000
                + digit5 * 10000
                + digit6 * 1000
                + digit7 * 100
                + digit8 * 10
                + digit9;
        if (digit10 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return possibleResult;
        }
        hasNext = hasNext();
        int digit11 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit11 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            if (negative) {
                if (-possibleResult > -INT_SIZE_BORDER || (-possibleResult == -INT_SIZE_BORDER && digit10 <= 8)) {
                    return possibleResult * 10 + digit10;
                }
            } else if (possibleResult < INT_SIZE_BORDER || (possibleResult == INT_SIZE_BORDER && digit10 <= 7)) {
                return possibleResult * 10 + digit10;
            }
        }
        hasNext = hasNext();
        //The Number is too big. Lets read it all and report in the exception
        StringBuilder number = new StringBuilder();
        if (negative) {
            number.insert(0, "-");
        }
        number.append(possibleResult).append(digit10);
        if (digit11 != -1) {
            int digit = digit11;
            number.append(digit);
            while (digit != -1) {
                digit = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
                hasNext = hasNext();
            }
        }
        if (hasNext) {
            currentIndex--;
        }
        throw new JsonException("Number is too big for an int value: " + number);
    }

    @Override
    public long readAsLong() {
        if (currentByte() == '-') {
            currentIndex++;
            return -parseLong(true);
        } else {
            return parseLong(false);
        }
    }

    private long parseLong(boolean negative) {
        if (currentIndex + 19 < bufferLength) {
            int digit1 = WHOLE_NUMBER_PARTS[currentByte()];
            if (digit1 == -1) {
                throw new IllegalStateException("Expected number, but was: " + (char) currentByte());
            }
            int digit2 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit2 == -1) {
                currentIndex--;
                return digit1;
            }
            int digit3 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit3 == -1) {
                currentIndex--;
                return digit1 * 10L + digit2;
            }
            int digit4 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit4 == -1) {
                currentIndex--;
                return digit1 * 100L + digit2 * 10L + digit3;
            }
            int digit5 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit5 == -1) {
                currentIndex--;
                return digit1 * 1000L + digit2 * 100L + digit3 * 10L + digit4;
            }
            int digit6 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit6 == -1) {
                currentIndex--;
                return digit1 * 10000L + digit2 * 1000L + digit3 * 100L + digit4 * 10L + digit5;
            }
            int digit7 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit7 == -1) {
                currentIndex--;
                return digit1 * 100000L + digit2 * 10000L + digit3 * 1000L + digit4 * 100L + digit5 * 10L + digit6;
            }
            int digit8 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit8 == -1) {
                currentIndex--;
                return digit1 * 1000000L + digit2 * 100000L + digit3 * 10000L + digit4 * 1000L + digit5 * 100L + digit6 * 10L + digit7;
            }
            int digit9 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit9 == -1) {
                currentIndex--;
                return digit1 * 10000000L + digit2 * 1000000L + digit3 * 100000L + digit4 * 10000L + digit5 * 1000L + digit6 * 100L
                        + digit7 * 10L + digit8;
            }
            int digit10 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit10 == -1) {
                currentIndex--;
                return digit1 * 100000000L
                        + digit2 * 10000000L
                        + digit3 * 1000000L
                        + digit4 * 100000L
                        + digit5 * 10000L
                        + digit6 * 1000L
                        + digit7 * 100L
                        + digit8 * 10L
                        + digit9;
            }
            int digit11 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit11 == -1) {
                currentIndex--;
                return digit1 * 1000000000L
                        + digit2 * 100000000L
                        + digit3 * 10000000L
                        + digit4 * 1000000L
                        + digit5 * 100000L
                        + digit6 * 10000L
                        + digit7 * 1000L
                        + digit8 * 100L
                        + digit9 * 10L
                        + digit10;
            }
            int digit12 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit12 == -1) {
                currentIndex--;
                return digit1 * 10000000000L
                        + digit2 * 1000000000L
                        + digit3 * 100000000L
                        + digit4 * 10000000L
                        + digit5 * 1000000L
                        + digit6 * 100000L
                        + digit7 * 10000L
                        + digit8 * 1000L
                        + digit9 * 100L
                        + digit10 * 10L
                        + digit11;
            }
            int digit13 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit13 == -1) {
                currentIndex--;
                return digit1 * 100000000000L
                        + digit2 * 10000000000L
                        + digit3 * 1000000000L
                        + digit4 * 100000000L
                        + digit5 * 10000000L
                        + digit6 * 1000000L
                        + digit7 * 100000L
                        + digit8 * 10000L
                        + digit9 * 1000L
                        + digit10 * 100L
                        + digit11 * 10L
                        + digit12;
            }
            int digit14 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit14 == -1) {
                currentIndex--;
                return digit1 * 1000000000000L
                        + digit2 * 100000000000L
                        + digit3 * 10000000000L
                        + digit4 * 1000000000L
                        + digit5 * 100000000L
                        + digit6 * 10000000L
                        + digit7 * 1000000L
                        + digit8 * 100000L
                        + digit9 * 10000L
                        + digit10 * 1000L
                        + digit11 * 100L
                        + digit12 * 10L
                        + digit13;
            }
            int digit15 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit15 == -1) {
                currentIndex--;
                return digit1 * 10000000000000L
                        + digit2 * 1000000000000L
                        + digit3 * 100000000000L
                        + digit4 * 10000000000L
                        + digit5 * 1000000000L
                        + digit6 * 100000000L
                        + digit7 * 10000000L
                        + digit8 * 1000000L
                        + digit9 * 100000L
                        + digit10 * 10000L
                        + digit11 * 1000L
                        + digit12 * 100L
                        + digit13 * 10L
                        + digit14;
            }
            int digit16 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit16 == -1) {
                currentIndex--;
                return digit1 * 100000000000000L
                        + digit2 * 10000000000000L
                        + digit3 * 1000000000000L
                        + digit4 * 100000000000L
                        + digit5 * 10000000000L
                        + digit6 * 1000000000L
                        + digit7 * 100000000L
                        + digit8 * 10000000L
                        + digit9 * 1000000L
                        + digit10 * 100000L
                        + digit11 * 10000L
                        + digit12 * 1000L
                        + digit13 * 100L
                        + digit14 * 10L
                        + digit15;
            }
            int digit17 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit17 == -1) {
                currentIndex--;
                return digit1 * 1000000000000000L
                        + digit2 * 100000000000000L
                        + digit3 * 10000000000000L
                        + digit4 * 1000000000000L
                        + digit5 * 100000000000L
                        + digit6 * 10000000000L
                        + digit7 * 1000000000L
                        + digit8 * 100000000L
                        + digit9 * 10000000L
                        + digit10 * 1000000L
                        + digit11 * 100000L
                        + digit12 * 10000L
                        + digit13 * 1000L
                        + digit14 * 100L
                        + digit15 * 10L
                        + digit16;
            }
            int digit18 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            long possibleResult = digit1 * 10000000000000000L
                    + digit2 * 1000000000000000L
                    + digit3 * 100000000000000L
                    + digit4 * 10000000000000L
                    + digit5 * 1000000000000L
                    + digit6 * 100000000000L
                    + digit7 * 10000000000L
                    + digit8 * 1000000000L
                    + digit9 * 100000000L
                    + digit10 * 10000000L
                    + digit11 * 1000000L
                    + digit12 * 100000L
                    + digit13 * 10000L
                    + digit14 * 1000L
                    + digit15 * 100L
                    + digit16 * 10L
                    + digit17;
            if (digit18 == -1) {
                currentIndex--;
                return possibleResult;
            }
            int digit19 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit19 == -1) {
                currentIndex--;
                if (negative) {
                    if (-possibleResult > -LONG_SIZE_BORDER || (-possibleResult == -LONG_SIZE_BORDER && digit18 <= 8)) {
                        return possibleResult * 10 + digit18;
                    }
                } else if (possibleResult < LONG_SIZE_BORDER || (possibleResult == LONG_SIZE_BORDER && digit18 <= 7)) {
                    return possibleResult * 10 + digit18;
                }
            }
            //TODO upravit na handling prilis dlouhych cisel
        }
        boolean hasNext = hasNext();
        int digit1 = WHOLE_NUMBER_PARTS[currentByte()];
        if (digit1 == -1) {
            throw new IllegalStateException("Expected number, but was: " + (char) currentByte());
        }
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit2 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit3 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10L + digit2;
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit4 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100L + digit2 * 10L + digit3;
        }
        hasNext = hasNext();
        int digit5 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit5 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 1000L + digit2 * 100L + digit3 * 10L + digit4;
        }
        hasNext = hasNext();
        int digit6 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit6 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10000L + digit2 * 1000L + digit3 * 100L + digit4 * 10L + digit5;
        }
        hasNext = hasNext();
        int digit7 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit7 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100000L + digit2 * 10000L + digit3 * 1000L + digit4 * 100L + digit5 * 10L + digit6;
        }
        hasNext = hasNext();
        int digit8 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit8 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 1000000L + digit2 * 100000L + digit3 * 10000L + digit4 * 1000L + digit5 * 100L + digit6 * 10L + digit7;
        }
        hasNext = hasNext();
        int digit9 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit9 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10000000L + digit2 * 1000000L + digit3 * 100000L + digit4 * 10000L + digit5 * 1000L + digit6 * 100L
                    + digit7 * 10L + digit8;
        }
        hasNext = hasNext();
        int digit10 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit10 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100000000L
                    + digit2 * 10000000L
                    + digit3 * 1000000L
                    + digit4 * 100000L
                    + digit5 * 10000L
                    + digit6 * 1000L
                    + digit7 * 100L
                    + digit8 * 10L
                    + digit9;
        }
        hasNext = hasNext();
        int digit11 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit11 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 1000000000L
                    + digit2 * 100000000L
                    + digit3 * 10000000L
                    + digit4 * 1000000L
                    + digit5 * 100000L
                    + digit6 * 10000L
                    + digit7 * 1000L
                    + digit8 * 100L
                    + digit9 * 10L
                    + digit10;
        }
        hasNext = hasNext();
        int digit12 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit12 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10000000000L
                    + digit2 * 1000000000L
                    + digit3 * 100000000L
                    + digit4 * 10000000L
                    + digit5 * 1000000L
                    + digit6 * 100000L
                    + digit7 * 10000L
                    + digit8 * 1000L
                    + digit9 * 100L
                    + digit10 * 10L
                    + digit11;
        }
        hasNext = hasNext();
        int digit13 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit13 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100000000000L
                    + digit2 * 10000000000L
                    + digit3 * 1000000000L
                    + digit4 * 100000000L
                    + digit5 * 10000000L
                    + digit6 * 1000000L
                    + digit7 * 100000L
                    + digit8 * 10000L
                    + digit9 * 1000L
                    + digit10 * 100L
                    + digit11 * 10L
                    + digit12;
        }
        hasNext = hasNext();
        int digit14 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit14 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 1000000000000L
                    + digit2 * 100000000000L
                    + digit3 * 10000000000L
                    + digit4 * 1000000000L
                    + digit5 * 100000000L
                    + digit6 * 10000000L
                    + digit7 * 1000000L
                    + digit8 * 100000L
                    + digit9 * 10000L
                    + digit10 * 1000L
                    + digit11 * 100L
                    + digit12 * 10L
                    + digit13;
        }
        hasNext = hasNext();
        int digit15 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit15 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10000000000000L
                    + digit2 * 1000000000000L
                    + digit3 * 100000000000L
                    + digit4 * 10000000000L
                    + digit5 * 1000000000L
                    + digit6 * 100000000L
                    + digit7 * 10000000L
                    + digit8 * 1000000L
                    + digit9 * 100000L
                    + digit10 * 10000L
                    + digit11 * 1000L
                    + digit12 * 100L
                    + digit13 * 10L
                    + digit14;
        }
        hasNext = hasNext();
        int digit16 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit16 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100000000000000L
                    + digit2 * 10000000000000L
                    + digit3 * 1000000000000L
                    + digit4 * 100000000000L
                    + digit5 * 10000000000L
                    + digit6 * 1000000000L
                    + digit7 * 100000000L
                    + digit8 * 10000000L
                    + digit9 * 1000000L
                    + digit10 * 100000L
                    + digit11 * 10000L
                    + digit12 * 1000L
                    + digit13 * 100L
                    + digit14 * 10L
                    + digit15;
        }
        hasNext = hasNext();
        int digit17 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit17 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 1000000000000000L
                    + digit2 * 100000000000000L
                    + digit3 * 10000000000000L
                    + digit4 * 1000000000000L
                    + digit5 * 100000000000L
                    + digit6 * 10000000000L
                    + digit7 * 1000000000L
                    + digit8 * 100000000L
                    + digit9 * 10000000L
                    + digit10 * 1000000L
                    + digit11 * 100000L
                    + digit12 * 10000L
                    + digit13 * 1000L
                    + digit14 * 100L
                    + digit15 * 10L
                    + digit16;
        }
        hasNext = hasNext();
        int digit18 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        long possibleResult = digit1 * 10000000000000000L
                + digit2 * 1000000000000000L
                + digit3 * 100000000000000L
                + digit4 * 10000000000000L
                + digit5 * 1000000000000L
                + digit6 * 100000000000L
                + digit7 * 10000000000L
                + digit8 * 1000000000L
                + digit9 * 100000000L
                + digit10 * 10000000L
                + digit11 * 1000000L
                + digit12 * 100000L
                + digit13 * 10000L
                + digit14 * 1000L
                + digit15 * 100L
                + digit16 * 10L
                + digit17;
        if (digit18 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return possibleResult;
        }
        hasNext = hasNext();
        int digit19 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit19 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            if (negative) {
                if (-possibleResult > -LONG_SIZE_BORDER || (-possibleResult == -LONG_SIZE_BORDER && digit18 <= 8)) {
                    return possibleResult * 10 + digit18;
                }
            } else if (possibleResult < LONG_SIZE_BORDER || (possibleResult == LONG_SIZE_BORDER && digit18 <= 7)) {
                return possibleResult * 10 + digit18;
            }
        }
        hasNext = hasNext();
        //The Number is too big. Lets read it all and report in the exception
        StringBuilder number = new StringBuilder();
        if (negative) {
            number.insert(0, "-");
        }
        number.append(possibleResult).append(digit18);
        if (digit19 != -1) {
            int digit = digit19;
            while (digit != -1) {
                number.append(digit);
                digit = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
                hasNext = hasNext();
            }
        }
        if (hasNext) {
            currentIndex--;
        }
        throw new JsonException("Number is too big for long value: " + number);
    }

    @Override
    public float readAsFloat() {
        boolean rollback = true;
        float result = readAsLong();
        byte nextByte = readNextByte();
        if (nextByte == '.') {
            int start = currentIndex;
            readNextByte();
            long fracPart = parseLong(false);
            int fracDigits = currentIndex - start;
            if (fracDigits >= POW_FLOAT_CACHE.length) {
                //Let Java handle POW, slower
                result += fracPart / (float) Math.pow(10, fracDigits);
            } else {
                result += fracPart / POW_FLOAT_CACHE[fracDigits];
            }
            rollback = hasNext();
            if (rollback) {
                nextByte = readNextByte();
            }
        }
        // Exponent part
        if (nextByte == 'e' || nextByte == 'E') {
            nextByte = readNextByte();
            boolean expNeg = false;
            if (nextByte == '+') {
                readNextByte();
            } else if (nextByte == '-') {
                expNeg = true;
                readNextByte();
            }
            int exp = parseInt(expNeg);
            if (exp != 0) {
                exp = expNeg ? -exp : exp;
                if (exp >= POW_FLOAT_CACHE.length || exp < 0) {
                    //Let Java handle POW, slower
                    result *= (float) Math.pow(10, exp);
                } else {
                    result *= POW_FLOAT_CACHE[exp];
                }
            }
        } else if (rollback) {
            --currentIndex;
        }
        return result;
    }

    @Override
    public double readAsDouble() {
        boolean rollback = true;
        double result = readAsLong();
        byte nextByte = hasNext() ? buffer[++currentIndex] : -1;
        if (nextByte == '.') {
            int start = currentIndex++;
            long fracPart = parseLong(false);
            int fracDigits = currentIndex - start;
            if (fracDigits >= POW_DOUBLE_CACHE.length) {
                //Let Java handle POW, slower
                result += fracPart / Math.pow(10, fracDigits);
            } else {
                result += fracPart / POW_DOUBLE_CACHE[fracDigits];
            }
            rollback = hasNext();
            if (rollback) {
                nextByte = buffer[++currentIndex];
            }
        }
        // Exponent part
        if (nextByte == 'e' || nextByte == 'E') {
            nextByte = readNextByte();
            boolean expNeg = false;
            if (nextByte == '+') {
                readNextByte();
            } else if (nextByte == '-') {
                expNeg = true;
                readNextByte();
            }
            int exp = parseInt(expNeg);
            if (exp != 0) {
                exp = expNeg ? -exp : exp;
                if (exp >= POW_DOUBLE_CACHE.length || exp < 0) {
                    //Let Java handle POW, slower
                    result *= Math.pow(10, exp);
                } else {
                    result *= POW_DOUBLE_CACHE[exp];
                }
            }
        } else if (rollback) {
            --currentIndex;
        }
        return result;
    }

    void ensure(int amount) {
        if (currentIndex + amount >= bufferLength) {
            throw new JsonException("Incomplete JSON.");
        }
    }

    void fetchData() {
        throw new JsonException("There are no more data to fetch. Incomplete JSON.");
    }

    @Override
    public boolean checkNull() {
        if (currentByte() == 'n') {
            ensure(3);
            if (buffer[++currentIndex] == 'u'
                    && buffer[++currentIndex] == 'l'
                    && buffer[++currentIndex] == 'l') {
                return true;
            }
            throw new JsonException("Expected value null at index: " + (currentIndex - 3));
        }
        return false;
    }

    @Override
    public int readStringAsHash() {
        if (currentByte() != '"') {
            throw new JsonException("This is supported only for Strings.");
        }
        //Based on recommended offset basis and prime values.
        int fnv1aHash = FNV_OFFSET_BASIS;
        byte b;
        currentIndex++;
        for ( ; currentIndex < bufferLength; currentIndex++) {
            b = buffer[currentIndex];
            if (b == '"') {
                return fnv1aHash;
            }
            fnv1aHash ^= (b & 0xFF);
            fnv1aHash *= FNV_PRIME;
        }
        throw new JsonException("Incomplete JSON.");
    }

    @Override
    public void skip() {
        switch (currentByte()) {
        case '"':
            skipStringValue();
            break;
        case '{':
            skipObject();
            break;
        case '[':
            skipArray();
            break;
        case '-':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            skipNumber();
            break;
        case 't':
        case 'n':
            ensure(3);
            currentIndex += 3;
            break;
        case 'f':
            ensure(4);
            currentIndex += 4;
            break;
        default:
            //TODO UPRAVIT
            throw new UnsupportedOperationException();
        }
    }

    void skipStringValue() {
        boolean isEscaped = false;
        for (int index = this.currentIndex + 1; index < this.bufferLength; index++) {
            byte b = this.buffer[index];
            if (b == '\\') {
                isEscaped = !isEscaped;
            } else if (b == '"') {
                if (!isEscaped) {
                    this.currentIndex = index;
                    return;
                }
            } else {
                isEscaped = false;
            }
        }
        //TODO UPRAVIT log hlaska
        throw new JsonException("Incomplete JSON or incorrect usage of the skip method");
    }

    private void skipObject() {
        byte b = nextToken();
        if (b == '}') {
            return;
        }
        do {
            if (b == '"') {
                skipStringValue();
                b = nextToken();
            } else {
                throw new JsonException("Key name expected, but found: " + (char) b + ". Error at index " + realIndex());
            }
            if (b != ':') {
                throw new JsonException("Colon expected after the key, but found: "
                                                + (char) b + ". Error at index " + realIndex());
            }
            nextToken();
            skip();
            b = nextToken();
        } while (b == ',');

        if (b == '}') {
            return;
        }
        throw new JsonException("Comma or the end of the object expected, but received " + (char) b);
    }

    private void skipArray() {
        byte b = nextToken();
        if (b == ']') {
            return;
        }
        do {
            skip();
            b = nextToken();
        } while (b == ',');

        if (b == ']') {
            return;
        }
        throw new JsonException("Comma or the end of the array expected, but received " + (char) b);
    }

    void skipNumber() {
        byte b;
        for (int index = this.currentIndex; index < this.bufferLength; index++) {
            b = this.buffer[index];
            //we do not need to validate whether this is a valid number since we are not processing it.
            //simply skip until you find any valid character after the number
            switch (b) {
            case ' ':
            case '\n':
            case '\t':
            case ',':
            case '}':
            case ']':
                this.currentIndex = index - 1;
                return;
            }
        }
    }

    public static int translateHex(byte b) {
        int val = HEX_DIGITS[b & 0xFF];
        if (val == -1) {
            throw new JsonException(b + " is not valid hex digit");
        }
        return val;
    }

}
