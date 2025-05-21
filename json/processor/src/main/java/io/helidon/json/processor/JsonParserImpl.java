package io.helidon.json.processor;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * TODO javadoc
 */
final class JsonParserImpl implements ReusableJsonParser {

    //We need this to check if the next number digit overflows int max capacity
    private static final int INT_SIZE_BORDER = Integer.MAX_VALUE / 10;
    private static final long LONG_SIZE_BORDER = Long.MAX_VALUE / 10;

    static final int[] WHOLE_NUMBER_PARTS = new int[127];
    static final float[] DECIMAL_NUMBER_PARTS = new float[127];
    public static final byte[] NULL_BYTES = {'n', 'u', 'l', 'l'};

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
        byte b;
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
        return currentIndex < bufferLength;
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

    private void processEscapedSequence(int bufferIndex) {
        byte c = readNextByte();
        switch (c) {
        case '\\':
            stringBuffer[bufferIndex] = '\\';
            break;
        case 'b':
            stringBuffer[bufferIndex] = '\b';
            break;
        case 't':
            stringBuffer[bufferIndex] = '\t';
            break;
        case 'n':
            stringBuffer[bufferIndex] = '\n';
            break;
        case 'f':
            stringBuffer[bufferIndex] = '\f';
            break;
        case 'r':
            stringBuffer[bufferIndex] = '\r';
            break;
        case '"':
            stringBuffer[bufferIndex] = '\"';
            break;
//        case 'u' -> {
//            boolean isExpectingLowSurrogate = false;
//            char tmp = (char) (
//                    (translateHex(readNextByte()) << 12) +
//                            (translateHex(readNextByte()) << 8) +
//                            (translateHex(readNextByte()) << 4) +
//                            translateHex(readNextByte()));
//            if (Character.isHighSurrogate(tmp)) {
//                if (isExpectingLowSurrogate) {
//                    throw new JsonException("invalid surrogate");
//                } else {
//                    isExpectingLowSurrogate = true;
//                }
//            } else if (Character.isLowSurrogate(tmp)) {
//                if (isExpectingLowSurrogate) {
//                    isExpectingLowSurrogate = false;
//                } else {
//                    throw new JsonException("invalid surrogate");
//                }
//            } else {
//                if (isExpectingLowSurrogate) {
//                    throw new JsonException("invalid surrogate");
//                }
//            }
//        }
        default:
            throw new JsonException("Invalid escaped character: " + c);
        }
    }

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
    public int readInt() {
        if (lastByte() == '-') {
            currentIndex = currentIndex + 1;
            return -parseInt(true);
        } else {
            return parseInt(false);
        }
//        int i = 0;
//        byte b = lastByte;
//        boolean negative = false;
//        if (lastByte == '-') {
//            negative = true;
//            i = -1;
//        } else {
//            numberBuffer[0] = WHOLE_NUMBER_PARTS[b];
//        }
//        int index = currentIndex;
//        while (true) {
//            b = buffer[index];
//            index = index + 1;
//            int digit = WHOLE_NUMBER_PARTS[b];
//            if (digit == -1) {
//                break;
//            }
//            numberBuffer[++i] = digit;
//        }
//
//        lastByte = b;
//        currentIndex = index - 1;
//        int result = calculateIntNumber(i, negative);
//        return negative ? -result : result;
    }

    private int parseInt(boolean negative) {
        int i = currentIndex;
        int digit1 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit1 == -1) {
            throw new JsonException("Expected number, but was: " + (char) buffer[i]);
        }
        int digit2 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit2 == -1) {
            return digit1;
        }
        int digit3 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit3 == -1) {
            currentIndex = --i;
            return digit1 * 10 + digit2;
        }
        int digit4 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit4 == -1) {
            currentIndex = --i;
            return digit1 * 100
                    + digit2 * 10
                    + digit3;
        }
        int digit5 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit5 == -1) {
            currentIndex = --i;
            return digit1 * 1000
                    + digit2 * 100
                    + digit3 * 10
                    + digit4;
        }
        int digit6 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit6 == -1) {
            currentIndex = --i;
            return digit1 * 10000
                    + digit2 * 1000
                    + digit3 * 100
                    + digit4 * 10
                    + digit5;
        }
        int digit7 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit7 == -1) {
            currentIndex = --i;
            return digit1 * 100000
                    + digit2 * 10000
                    + digit3 * 1000
                    + digit4 * 100
                    + digit5 * 10
                    + digit6;
        }
        int digit8 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit8 == -1) {
            currentIndex = --i;
            return digit1 * 1000000
                    + digit2 * 100000
                    + digit3 * 10000
                    + digit4 * 1000
                    + digit5 * 100
                    + digit6 * 10
                    + digit7;
        }
        int digit9 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit9 == -1) {
            currentIndex = --i;
            return digit1 * 10000000
                    + digit2 * 1000000
                    + digit3 * 100000
                    + digit4 * 10000
                    + digit5 * 1000
                    + digit6 * 100
                    + digit7 * 10
                    + digit8;
        }
        int digit10 = WHOLE_NUMBER_PARTS[buffer[i++]];
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
            currentIndex = --i;
            return possibleResult;
        }
        int digit11 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit11 == -1) {
            currentIndex = --i;
            if (negative) {
                if (-possibleResult > -INT_SIZE_BORDER || (-possibleResult == -INT_SIZE_BORDER && digit10 <= 8)) {
                    return possibleResult * 10 + digit10;
                }
            } else if (possibleResult < INT_SIZE_BORDER || (possibleResult == INT_SIZE_BORDER && digit10 <= 7)) {
                return possibleResult * 10 + digit10;
            }
        }
        //The Number is too big. Lets read it all and report in the exception
        i++;
        StringBuilder number = new StringBuilder();
        if (negative) {
            number.insert(0, "-");
        }
        number.append(possibleResult).append(digit10);
        if (digit11 != -1) {
            int digit = digit11;
            while (digit != -1) {
                number.append(digit);
                digit = WHOLE_NUMBER_PARTS[buffer[i++]];
            }
        }
        currentIndex = --i;
        throw new JsonException("Number is too big for int value: " + number);
    }

    @Override
    public long readLong() {
        if (lastByte() == '-') {
            currentIndex = currentIndex + 1;
            return -parseLong(true);
        } else {
            return parseLong(false);
        }
    }

    private long parseLong(boolean negative) {
        int i = currentIndex;
        int digit1 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit1 == -1) {
            throw new IllegalStateException("Expected number, but was: " + (char) buffer[i]);
        }
        int digit2 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit2 == -1) {
            currentIndex = --i;
            return digit1;
        }
        int digit3 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit3 == -1) {
            currentIndex = --i;
            return digit1 * 10L + digit2;
        }
        int digit4 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit4 == -1) {
            currentIndex = --i;
            return digit1 * 100L + digit2 * 10L + digit3;
        }
        int digit5 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit5 == -1) {
            currentIndex = --i;
            return digit1 * 1000L + digit2 * 100L + digit3 * 10L + digit4;
        }
        int digit6 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit6 == -1) {
            currentIndex = --i;
            return digit1 * 10000L + digit2 * 1000L + digit3 * 100L + digit4 * 10L + digit5;
        }
        int digit7 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit7 == -1) {
            currentIndex = --i;
            return digit1 * 100000L + digit2 * 10000L + digit3 * 1000L + digit4 * 100L + digit5 * 10L + digit6;
        }
        int digit8 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit8 == -1) {
            currentIndex = --i;
            return digit1 * 1000000L + digit2 * 100000L + digit3 * 10000L + digit4 * 1000L + digit5 * 100L + digit6 * 10L + digit7;
        }
        int digit9 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit9 == -1) {
            currentIndex = --i;
            return digit1 * 10000000L + digit2 * 1000000L + digit3 * 100000L + digit4 * 10000L + digit5 * 1000L + digit6 * 100L
                    + digit7 * 10L + digit8;
        }
        int digit10 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit10 == -1) {
            currentIndex = --i;
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
        int digit11 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit11 == -1) {
            currentIndex = --i;
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
        int digit12 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit12 == -1) {
            currentIndex = --i;
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
        int digit13 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit13 == -1) {
            currentIndex = --i;
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
        int digit14 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit14 == -1) {
            currentIndex = --i;
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
        int digit15 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit15 == -1) {
            currentIndex = --i;
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
        int digit16 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit16 == -1) {
            currentIndex = --i;
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
        int digit17 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit17 == -1) {
            currentIndex = --i;
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
        int digit18 = WHOLE_NUMBER_PARTS[buffer[i++]];
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
            currentIndex = --i;
            return possibleResult;
        }
        int digit19 = WHOLE_NUMBER_PARTS[buffer[i++]];
        if (digit19 == -1) {
            currentIndex = --i;
            if (negative) {
                if (-possibleResult > -LONG_SIZE_BORDER || (-possibleResult == -LONG_SIZE_BORDER && digit18 <= 8)) {
                    return possibleResult * 10 + digit18;
                }
            } else if (possibleResult < LONG_SIZE_BORDER || (possibleResult == LONG_SIZE_BORDER && digit18 <= 7)) {
                return possibleResult * 10 + digit18;
            }
        }
        //The Number is too big. Lets read it all and report in the exception
        i++;
        StringBuilder number = new StringBuilder();
        if (negative) {
            number.insert(0, "-");
        }
        number.append(possibleResult).append(digit18);
        if (digit19 != -1) {
            int digit = digit19;
            while (digit != -1) {
                number.append(digit);
                digit = WHOLE_NUMBER_PARTS[buffer[i++]];
            }
        }
        currentIndex = --i;
        throw new JsonException("Number is too big for long value: " + number);
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
            throw new JsonException("Key name expected after object start, but found: " + Character.toString(lastByte()) + ". "
                                            + "Error at index " + realIndex());
        }
        if (b != ':') {
            throw new JsonException("Colon expected after the key, but found: " + Character.toString(lastByte()) + ". Error at "
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
