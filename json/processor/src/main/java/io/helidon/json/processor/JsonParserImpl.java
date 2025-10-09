package io.helidon.json.processor;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * TODO javadoc
 */
final class JsonParserImpl implements ReusableJsonParser {

    //We need this to check if the next number digit overflows int max capacity
    private static final byte BYTE_SIZE_BORDER = Byte.MAX_VALUE / 10;
    private static final short SHORT_SIZE_BORDER = Short.MAX_VALUE / 10;
    private static final int INT_SIZE_BORDER = Integer.MAX_VALUE / 10;
    private static final long LONG_SIZE_BORDER = Long.MAX_VALUE / 10;
    private static final byte[] EMPTY_BUFFER = new byte[0];

    static final int[] WHOLE_NUMBER_PARTS = new int[127];
    static final float[] DECIMAL_NUMBER_PARTS = new float[127];
    public static final byte[] NULL_BYTES = {'n', 'u', 'l', 'l'};

    private static final double[] POW_CACHE = new double[] {
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
        Arrays.fill(DECIMAL_NUMBER_PARTS, -1);

        for (int i = '0'; i <= '9'; ++i) {
            WHOLE_NUMBER_PARTS[i] = (i - '0');
            DECIMAL_NUMBER_PARTS[i] = (i - '0');
        }
    }

    static final boolean[] WHITESPACE_CHARS = new boolean[256];

    static {
        WHITESPACE_CHARS[9 + 128] = true;
        WHITESPACE_CHARS[10 + 128] = true;
        WHITESPACE_CHARS[11 + 128] = true;
        WHITESPACE_CHARS[12 + 128] = true;
        WHITESPACE_CHARS[13 + 128] = true;
        WHITESPACE_CHARS[32 + 128] = true;
        WHITESPACE_CHARS[-96 + 128] = true;
        WHITESPACE_CHARS[-31 + 128] = true;
        WHITESPACE_CHARS[-30 + 128] = true;
        WHITESPACE_CHARS[-29 + 128] = true;
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

    private final char[] stringBuffer = new char[64];
    private final int[] numberBuffer = new int[64];
    byte[] buffer;
    int currentIndex = -1;
    int bufferLength;

    JsonParserImpl() {
        this(EMPTY_BUFFER);
    }

    JsonParserImpl(String json) {
        //        this(json.getBytes(StandardCharsets.UTF_8));
        this(json.getBytes());
    }

    JsonParserImpl(byte[] buffer) {
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
    public byte lastByte() {
        return buffer[currentIndex];
    }

    @Override
    public byte nextToken() {
        //Optimization for faster reading data without a space
        //No loop is used.
        byte b = readNextByte();
        switch (b) {
        case '\r':
        case '\t':
        case '\n':
        case ' ':
            break;
        default:
            return b;
        }
        //If since space or why character was used between tokens, we should still try to optimize
        b = readNextByte();
        switch (b) {
        case '\r':
        case '\t':
        case '\n':
        case ' ':
            break;
        default:
            return b;
        }
        //We dont know how many spaces, new lines etc is there present, lets start looping
        for (int i = currentIndex + 1; i < bufferLength; i++) {
            b = buffer[i];
            switch (b) {
            case '\r':
            case '\t':
            case '\n':
            case ' ':
                continue;
            default:
                currentIndex = i;
                return b;
            }
        }
        throw new JsonException("Json incomplete!");
    }

    boolean hasNext() {
        return currentIndex + 1 < bufferLength;
    }

    @Override
    public byte readNextByte() {
        return buffer[++currentIndex];
    }

    @Override
    public JsonObject readObject() {
        Map<String, Object> properties = new HashMap<>();
        byte b = currentIndex == 0 ? nextToken() : lastByte();
        if (b != '{') {
            throw new JsonException("Expected start of the object");
        }
        b = nextToken();
        if (b == '}') {
            return new JsonObject(properties);
        }
        while (hasNext()) {
            String keyName;
            if (b == '"') {
                keyName = readString();
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
            case '{':
                //            case '[':
                properties.put(keyName, readObject());
                b = nextToken();
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
                properties.put(keyName, readJsonNumber());
                while (DECIMAL_NUMBER_PARTS[b] != -1) {//For example if the number was in decimal format
                    b = nextToken();
                }
                break;
            case 'n':
                checkNull();
                properties.put(keyName, null);
                b = nextToken();
                break;
            case 't':
                checkTrue();
                properties.put(keyName, true);
                b = nextToken();
                break;
            case 'f':
                checkFalse();
                properties.put(keyName, false);
                b = nextToken();
                break;
            default:
                throw new JsonException("Unexpected token at index: " + realIndex());
            }
            if (b == '}') {
                return new JsonObject(properties);
            } else if (b != ',') {
                throw new JsonException("Comma or } expected at index: " + realIndex() + ", but was: " + Character.toString(b));
            }
            b = nextToken();
        }
        throw new JsonException("Unexpected end of the object at index: " + realIndex() + ", but was: " + Character.toString(b));
    }

    int realIndex() {
        return currentIndex - 1;
    }

    @Override
    public String readString() {
        if (checkNull()) {
            return null;
        }
        byte b;
        int index = currentIndex + 1;
        search:
        for (int i = 0; i < stringBuffer.length; i++, index++) {
            b = buffer[index];
            switch (b) {
            case '"':
                currentIndex = index;
                return new String(stringBuffer, 0, i);
            case '\\':
                break search;
            }
            stringBuffer[i] = (char) b;
        }
        //TODO UPRAVIT pridat zpracovani slozitejsich Stringu
        throw new IllegalStateException();
        //        int i = 0;
        //        byte c = readNextByte();
        //        while (c != '"') {
        //            if (c == '\\') {
        //                processEscapedSequence(i++);
        //                c = readNextByte();
        //                continue;
        //            }
        //            stringBuffer[i++] = (char) c;
        //            c = readNextByte();
        //        }
        //        return new String(Arrays.copyOf(stringBuffer, i));
    }

    //    @Override
    //    public byte[] readAsBytes() {
    //        if (checkNull()) {
    //            return NULL_BYTES;
    //        }
    //        int start = currentIndex;
    //        int end = -1;
    //        if (lastByte() == '"') {
    //            start++;
    //            byte b;
    //            for (int i = currentIndex + 1; i < bufferLength; i++) {
    //                b = buffer[i];
    //                if (b == '"') {
    //                    end = i - 1;
    //                    currentIndex = i;
    //                    break;
    //                }
    //            }
    //        } else {
    //            byte b;
    //            for (int i = currentIndex + 1; i < bufferLength; i++) {
    //                b = buffer[i];
    //                switch (b) {
    //                    case ',':
    //                    case ':':
    //                    case '}':
    //                    case ']':
    //                    case ' ':
    //                        end = i - 1;
    //                        currentIndex = i;
    //                        break;
    //                }
    //            }
    //        }
    //        return Arrays.copyOfRange(buffer, start, end);
    //    }

//    private void processEscapedSequence(int bufferIndex) {
//        byte c = readNextByte();
//        switch (c) {
//        case '\\':
//            stringBuffer[bufferIndex] = '\\';
//            break;
//        case 'b':
//            stringBuffer[bufferIndex] = '\b';
//            break;
//        case 't':
//            stringBuffer[bufferIndex] = '\t';
//            break;
//        case 'n':
//            stringBuffer[bufferIndex] = '\n';
//            break;
//        case 'f':
//            stringBuffer[bufferIndex] = '\f';
//            break;
//        case 'r':
//            stringBuffer[bufferIndex] = '\r';
//            break;
//        case '"':
//            stringBuffer[bufferIndex] = '\"';
//            break;
//        //        case 'u' -> {
//        //            boolean isExpectingLowSurrogate = false;
//        //            char tmp = (char) (
//        //                    (translateHex(readNextByte()) << 12) +
//        //                            (translateHex(readNextByte()) << 8) +
//        //                            (translateHex(readNextByte()) << 4) +
//        //                            translateHex(readNextByte()));
//        //            if (Character.isHighSurrogate(tmp)) {
//        //                if (isExpectingLowSurrogate) {
//        //                    throw new JsonException("invalid surrogate");
//        //                } else {
//        //                    isExpectingLowSurrogate = true;
//        //                }
//        //            } else if (Character.isLowSurrogate(tmp)) {
//        //                if (isExpectingLowSurrogate) {
//        //                    isExpectingLowSurrogate = false;
//        //                } else {
//        //                    throw new JsonException("invalid surrogate");
//        //                }
//        //            } else {
//        //                if (isExpectingLowSurrogate) {
//        //                    throw new JsonException("invalid surrogate");
//        //                }
//        //            }
//        //        }
//        default:
//            throw new JsonException("Invalid escaped character: " + c);
//        }
//    }

    @Override
    public JsonNumber readJsonNumber() {
        return new JsonNumber(readNumberAsArray());
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
                byteRollback();
                char[] numberBuffer = new char[i];
                System.arraycopy(stringBuffer, 0, numberBuffer, 0, i);
                return numberBuffer;
            }
        }
    }

    @Override
    public boolean readAsBoolean() {
        switch (lastByte()) {
        case 't':
            if (buffer[currentIndex + 1] == 'r'
                    && buffer[currentIndex + 2] == 'u'
                    && buffer[currentIndex + 3] == 'e') {
                currentIndex = currentIndex + 3;
                return true;
            }
            throw new JsonException("Expected value true at index: " + realIndex());
        case 'f':
            if (buffer[currentIndex + 1] == 'a'
                    && buffer[currentIndex + 2] == 'l'
                    && buffer[currentIndex + 3] == 's'
                    && buffer[currentIndex + 4] == 'e') {
                currentIndex = currentIndex + 4;
                return false;
            }
            throw new JsonException("Expected value false at index: " + realIndex());
        default:
            throw new JsonException("Expected boolean value at index: " + realIndex());
        }
    }

    @Override
    public byte readAsByte() {
        if (lastByte() == '-') {
            currentIndex = currentIndex + 1;
            return (byte) -parseByte(true);
        } else {
            return parseByte(false);
        }
    }

    private byte parseByte(boolean negative) {
        int digit1 = WHOLE_NUMBER_PARTS[lastByte()];
        if (digit1 == -1) {
            throw new JsonException("Expected number, but was: " + (char) lastByte());
        }
        boolean hasNext = hasNext();
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit2 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (byte) digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        int possibleResult = digit1 * 10 + digit2;
        if (digit3 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (byte) possibleResult;
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
                digit = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        if (lastByte() == '-') {
            currentIndex = currentIndex + 1;
            return (short) -parseShort(true);
        } else {
            return parseShort(false);
        }
    }

    private short parseShort(boolean negative) {
        int digit1 = WHOLE_NUMBER_PARTS[lastByte()];
        if (digit1 == -1) {
            throw new JsonException("Expected number, but was: " + (char) lastByte());
        }
        boolean hasNext = hasNext();
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit2 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (short) digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit3 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (short) (digit1 * 10 + digit2);
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit4 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return (short) (digit1 * 100 + digit2 * 10 + digit3);
        }
        hasNext = hasNext();
        int digit5 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        short possibleResult = (short) (digit1 * 1000 + digit2 * 100 + digit3 * 10 + digit4);
        if (digit5 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return possibleResult;
        }
        hasNext = hasNext();
        int digit6 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
                digit = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        if (lastByte() == '-') {
            currentIndex = currentIndex + 1;
            return -parseInt(true);
        } else {
            return parseInt(false);
        }
    }

    private int parseInt(boolean negative) {
        int digit1 = WHOLE_NUMBER_PARTS[lastByte()];
        if (digit1 == -1) {
            throw new JsonException("Expected number, but was: " + (char) lastByte());
        }
        boolean hasNext = hasNext();
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit2 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit3 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10 + digit2;
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit4 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100
                    + digit2 * 10
                    + digit3;
        }
        hasNext = hasNext();
        int digit5 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit6 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit7 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit8 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit9 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit10 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit11 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
            while (digit != -1) {
                number.append(digit);
                digit = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
                hasNext = hasNext();
            }
        }
        if (hasNext) {
            currentIndex--;
        }
        throw new JsonException("Number is too big for int value: " + number);
    }

    @Override
    public long readAsLong() {
        if (lastByte() == '-') {
            currentIndex = currentIndex + 1;
            return -parseLong(true);
        } else {
            return parseLong(false);
        }
    }

    private long parseLong(boolean negative) {
        boolean hasNext = hasNext();
        int digit1 = WHOLE_NUMBER_PARTS[lastByte()];
        if (digit1 == -1) {
            throw new IllegalStateException("Expected number, but was: " + (char) lastByte());
        }
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit2 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit3 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10L + digit2;
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit4 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100L + digit2 * 10L + digit3;
        }
        hasNext = hasNext();
        int digit5 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit5 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 1000L + digit2 * 100L + digit3 * 10L + digit4;
        }
        hasNext = hasNext();
        int digit6 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit6 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10000L + digit2 * 1000L + digit3 * 100L + digit4 * 10L + digit5;
        }
        hasNext = hasNext();
        int digit7 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit7 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 100000L + digit2 * 10000L + digit3 * 1000L + digit4 * 100L + digit5 * 10L + digit6;
        }
        hasNext = hasNext();
        int digit8 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit8 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 1000000L + digit2 * 100000L + digit3 * 10000L + digit4 * 1000L + digit5 * 100L + digit6 * 10L + digit7;
        }
        hasNext = hasNext();
        int digit9 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
        if (digit9 == -1) {
            if (hasNext) {
                currentIndex--;
            }
            return digit1 * 10000000L + digit2 * 1000000L + digit3 * 100000L + digit4 * 10000L + digit5 * 1000L + digit6 * 100L
                    + digit7 * 10L + digit8;
        }
        hasNext = hasNext();
        int digit10 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit11 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit12 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit13 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit14 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit15 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit16 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit17 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit18 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        int digit19 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
                digit = hasNext ? WHOLE_NUMBER_PARTS[readNextByte()] : -1;
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
        return 0;
    }

    @Override
    public double readAsDouble() {
        boolean rollback = true;
        double result = readAsLong();
        byte nextByte = readNextByte();
        if (nextByte == '.') {
            int start = currentIndex;
            readNextByte();
            long fracPart = parseLong(false);
            int fracDigits = currentIndex - start;
            if (fracDigits >= POW_CACHE.length) {
                //Let Java handle POW, slower
                result += fracPart / Math.pow(10, fracDigits);
            } else {
                result += fracPart / POW_CACHE[fracDigits];
            }
            rollback = hasNext();
            if (rollback) {
                nextByte = readNextByte();
            }
        }
        // Exponent part
        if (nextByte == 'e'|| nextByte == 'E') {
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
                if (exp >= POW_CACHE.length || exp < 0) {
                    //Let Java handle POW, slower
                    result *= Math.pow(10, exp);
                } else {
                    result *= POW_CACHE[exp];
                }
            }
        } else if (rollback) {
            byteRollback();
        }
        return result;
    }

    @Override
    public boolean checkNull() {
        if (lastByte() == 'n') {
            if (buffer[currentIndex + 1] == 'u'
                    && buffer[currentIndex + 2] == 'l'
                    && buffer[currentIndex + 3] == 'l') {
                currentIndex = currentIndex + 3;
                return true;
            }
            throw new JsonException("Expected value null at index: " + realIndex());
        }
        return false;
    }

    @Override
    public boolean checkTrue() {
        if (lastByte() == 't') {
            if (buffer[currentIndex + 1] == 'r'
                    && buffer[currentIndex + 2] == 'u'
                    && buffer[currentIndex + 3] == 'e') {
                currentIndex = currentIndex + 3;
                return true;
            }
            throw new JsonException("Expected value true at index: " + realIndex());
        }
        return false;
    }

    @Override
    public boolean checkFalse() {
        if (lastByte() == 'f') {
            if (buffer[currentIndex + 1] == 'a'
                    && buffer[currentIndex + 2] == 'l'
                    && buffer[currentIndex + 3] == 's'
                    && buffer[currentIndex + 4] == 'e') {
                currentIndex = currentIndex + 4;
                return true;
            }
            throw new JsonException("Expected value false at index: " + realIndex());
        }
        return false;
    }

    @Override
    public int readStringAsHash() {
        if (lastByte() != '"') {
            throw new JsonException("This is supported only for Strings.");
        }
        //Based on recommended offset basis and prime values.
        long fnv1aHash = 2166136261L;
        int i = currentIndex + 1;
        byte b = buffer[i];
        while (b != '"') { //pridat prepinac na escapenuty \"
            fnv1aHash ^= b;
            fnv1aHash *= 16777619;
            b = buffer[++i];
        }
        currentIndex = i;
        return (int) fnv1aHash;
    }

    @Override
    public void byteRollback() {
        --currentIndex;
    }

    @Override
    public void skip() {
        switch (lastByte()) {
        case '"':
            skipStringValue();
            break;
        case '{':
            skipObject();
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
            currentIndex += 3;
            break;
        case 'f':
            currentIndex += 4;
            break;
        default:
            //TODO UPRAVIT
            throw new UnsupportedOperationException();
        }
    }

    private void skipStringValue() {
        boolean isEscaped = false;
        for (int index = this.currentIndex + 1; index < this.bufferLength; index++) {
            byte b = this.buffer[index];
            switch (b) {
            case '\\':
                isEscaped = !isEscaped;
                break;
            case '"':
                if (!isEscaped) {
                    this.currentIndex = index;
                    return;
                }
            }
        }
        //TODO UPRAVIT log hlaska
        throw new JsonException("Incomplete JSON or incorrect usage of skip method");
    }

    //TODO UPRAVIT PRIO
    private void skipObject() {
        byte b = nextToken();
        if (b == '}') {
            return;
        }
        if (b == '"') {
            skipStringValue();
            b = nextToken();
        } else {
            throw new JsonException("Key name expected after object start, but found: " + Character.toString(lastByte()) +
                                            ". "
                                            + "Error at index " + realIndex());
        }
        if (b != ':') {
            throw new JsonException("Colon expected after the key, but found: " + Character.toString(lastByte()) + ". Error"
                                            + " at "
                                            + "index " + realIndex());
        }
        b = nextToken();
        skip();
        b = nextToken();
        if (b == '}') {
            return;
        }
        //TODO UPRAVIT
        throw new IllegalStateException();
    }

    private void skipNumber() {
        byte b;
        for (int index = this.currentIndex + 1; index < this.bufferLength; index++) {
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
                this.currentIndex = index;
                return;
            }
        }
    }

    public static int translateHex(final byte b) {
        int val = HEX_DIGITS[b];
        if (val == -1) {
            throw new IndexOutOfBoundsException(b + " is not valid hex digit");
        }
        return val;
    }

}
