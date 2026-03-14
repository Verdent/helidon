package io.helidon.json.simd;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import io.helidon.common.buffers.BufferData;
import io.helidon.json.JsonException;
import io.helidon.json.JsonNumber;
import io.helidon.json.JsonParserBase;
import io.helidon.json.JsonString;
import io.helidon.json.Parsers;

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.VectorShuffle;

import static jdk.incubator.vector.ByteVector.SPECIES_512;

final class JsonParserSimd extends JsonParserBase {

    static final int CHUNK_SIZE = SPECIES_512.vectorByteSize();
    private static final int FNV_OFFSET_BASIS = 0x811c9dc5;
    private static final int FNV_PRIME = 0x01000193;
    private static final byte BYTE_SIZE_BORDER = Byte.MAX_VALUE / 10;
    private static final short SHORT_SIZE_BORDER = Short.MAX_VALUE / 10;
    private static final int INT_SIZE_BORDER = Integer.MAX_VALUE / 10;
    private static final long LONG_SIZE_BORDER = Long.MAX_VALUE / 10;
    private static final int DOT_MARK = -2;

    private static final int STATE_IN_STRING = 1;
    private static final int STATE_ODD_BACKSLASH_RUN = 1 << 1;
    private static final int STATE_PSEUDO_STRUCTURAL_PREDECESSOR = 1 << 2;
    static final int INITIAL_STATE = STATE_PSEUDO_STRUCTURAL_PREDECESSOR;

    private static final ByteVector WHITESPACE_TABLE;
    private static final ByteVector STRUCTURAL_TABLE;
    private static final byte[] TAIL_PADDING = new byte[CHUNK_SIZE];
    private static final int[] WHOLE_NUMBER_PARTS = new int[256];
    private static final boolean[] VALID_NUMBER_PARTS = new boolean[256];
    private static final double[] POW10_DOUBLE_CACHE = {
            1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0,
            100000000.0, 1000000000.0, 10000000000.0, 100000000000.0,
            1000000000000.0, 10000000000000.0, 100000000000000.0,
            1000000000000000.0, 10000000000000000.0, 100000000000000000.0,
            1000000000000000000.0, 10000000000000000000.0, 1.0e20, 1.0e21, 1.0e22
    };
    private static final int POW10_DOUBLE_CACHE_SIZE = POW10_DOUBLE_CACHE.length;

    static {
        byte x = (byte) 0x80;

        byte[] ws = new byte[] {
                ' ', x, x, x, x, x, x, x,
                x, '\t', '\n', x, x, '\r', x, x
        };

        byte[] st = new byte[] {
                x, x, x, x, x, x, x, x,
                x, x, ':', '{', ',', '}', x, x
        };

        WHITESPACE_TABLE = ByteVector.fromArray(SPECIES_512, tile(ws), 0);
        STRUCTURAL_TABLE = ByteVector.fromArray(SPECIES_512, tile(st), 0);

        Arrays.fill(WHOLE_NUMBER_PARTS, -1);
        for (int i = '0'; i <= '9'; ++i) {
            WHOLE_NUMBER_PARTS[i] = i - '0';
            VALID_NUMBER_PARTS[i] = true;
        }
        WHOLE_NUMBER_PARTS['.'] = DOT_MARK;
        VALID_NUMBER_PARTS['-'] = true;
        VALID_NUMBER_PARTS['+'] = true;
        VALID_NUMBER_PARTS['.'] = true;
        VALID_NUMBER_PARTS['e'] = true;
        VALID_NUMBER_PARTS['E'] = true;
    }

    private final byte[] buffer;
    private final int start;
    private final int length;
    private final int[] tape;
    private final int tapeLength;
    private final boolean endsInsideString;
    private final boolean endsWithOddBackslashRun;
    private final boolean endsAfterPseudoStructuralPredecessor;
    private final int limit;

    private int currentIndex;
    private int currentTapeIndex;
    private int mark = -1;
    private int markedTapeIndex = -1;
    private boolean replayMarked;
    private int stringBufferLength = 64;
    private char[] stringBuffer = new char[stringBufferLength];
    private boolean expectLowSurrogate;

    JsonParserSimd(byte[] buffer) {
        this(buffer, 0, buffer.length);
    }

    JsonParserSimd(byte[] buffer, int start, int length) {
        Objects.requireNonNull(buffer, "buffer");
        Objects.checkFromIndexSize(start, length, buffer.length);

        this.buffer = buffer;
        this.start = start;
        this.length = length;
        this.limit = start + length;
        StructuralTape structuralTape = buildTape(buffer, start, length, INITIAL_STATE);
        this.tape = structuralTape.tape();
        this.tapeLength = structuralTape.tapeLength();
        int nextState = structuralTape.nextState();
        this.endsInsideString = hasState(nextState, STATE_IN_STRING);
        this.endsWithOddBackslashRun = hasState(nextState, STATE_ODD_BACKSLASH_RUN);
        this.endsAfterPseudoStructuralPredecessor = hasState(nextState, STATE_PSEUDO_STRUCTURAL_PREDECESSOR);
        this.currentIndex = start;
        this.currentTapeIndex = tapeLength > 0 && tape[0] == 0 ? 0 : -1;
    }

    int[] tape() {
        return tape;
    }

    int tapeLength() {
        return tapeLength;
    }

    boolean endsInsideString() {
        return endsInsideString;
    }

    boolean endsWithOddBackslashRun() {
        return endsWithOddBackslashRun;
    }

    boolean endsAfterPseudoStructuralPredecessor() {
        return endsAfterPseudoStructuralPredecessor;
    }

    byte[] buffer() {
        return buffer;
    }

    int start() {
        return start;
    }

    int length() {
        return length;
    }

    @Override
    public boolean hasNext() {
        return currentIndex + 1 < limit;
    }

    @Override
    public byte nextToken() {
        int nextTapeIndex = currentTapeIndex + 1;
        int currentOffset = currentIndex - start;
        while (nextTapeIndex < tapeLength && tape[nextTapeIndex] <= currentOffset) {
            nextTapeIndex++;
        }
        if (nextTapeIndex >= tapeLength) {
            throw createException("Unexpected end of the JSON found");
        }
        currentTapeIndex = nextTapeIndex;
        currentIndex = start + tape[nextTapeIndex];
        return buffer[currentIndex];
    }

    @Override
    public byte currentByte() {
        return buffer[currentIndex];
    }

    @Override
    public JsonString readJsonString() {
        if (currentByte() != '"') {
            throw createException("Expected start of string", currentByte());
        }
        int stringStart = currentIndex + 1;
        skipString();
        return JsonString.create(buffer, stringStart, currentIndex - stringStart);
    }

    @Override
    public JsonNumber readJsonNumber() {
        int numberStart = currentIndex;
        skipNumber();
        return JsonNumber.create(buffer, numberStart, currentIndex - numberStart + 1);
    }

    @Override
    public String readString() {
        if (checkNull()) {
            return null;
        } else if (currentByte() != '"') {
            throw createException("Expected start of string", currentByte());
        }
        int index = ++currentIndex;
        int readableBytes = limit - currentIndex;
        int firstRun = Math.min(stringBufferLength, readableBytes);
        byte b;
        int stringBufferIndex = 0;
        for (; stringBufferIndex < firstRun; stringBufferIndex++) {
            b = buffer[index++];
            if (b == '"') {
                currentIndex = --index;
                return new String(stringBuffer, 0, stringBufferIndex);
            } else if ((b ^ '\\') < 1) {
                currentIndex = --index;
                break;
            }
            stringBuffer[stringBufferIndex] = (char) b;
        }
        if (stringBufferIndex == firstRun) {
            currentIndex = index;
        }

        if (stringBufferIndex == stringBufferLength) {
            increaseStringBuffer();
        }

        for (; currentIndex < limit; currentIndex++) {
            b = buffer[currentIndex];
            if (b == '\\') {
                stringBuffer[stringBufferIndex++] = processEscapedSequence();
            } else if (expectLowSurrogate) {
                throw createException("Low surrogate must follow the high surrogate.", b);
            } else if (b == '"') {
                return new String(stringBuffer, 0, stringBufferIndex);
            } else if ((b & 0x80) == 0) {
                stringBuffer[stringBufferIndex++] = (char) b;
            } else {
                stringBufferIndex = decodeUtf8(stringBufferIndex, b);
            }
            if (stringBufferIndex == stringBufferLength) {
                increaseStringBuffer();
            }
        }
        throw createException("End of the string expected. Incomplete JSON");
    }

    @Override
    public int readStringAsHash() {
        int b = buffer[currentIndex] & 0xFF;
        if (b != '"') {
            throw createException("Hash calculation is intended only for String values");
        }
        int fnv1aHash = FNV_OFFSET_BASIS;
        currentIndex++;
        for (int i = currentIndex; i < limit; i++) {
            b = buffer[i] & 0xFF;
            if (b == '"') {
                currentIndex = i;
                return fnv1aHash;
            }
            fnv1aHash ^= b;
            fnv1aHash *= FNV_PRIME;
        }
        throw createException("Unexpected end of string value. Probably incomplete JSON");
    }

    @Override
    public char readChar() {
        if (currentByte() != '"') {
            throw createException("Start of a string expected", currentByte());
        }
        ensure(1);
        byte b = buffer[++currentIndex];
        char c;
        if (b == '\\') {
            c = processEscapedSequence();
        } else if ((b & 0x80) == 0) {
            c = (char) b;
        } else {
            c = decodeUtf8ToChar(b);
        }
        ensure(1);
        if (buffer[++currentIndex] != '"') {
            throw createException("End of a string expected", currentByte());
        }
        return c;
    }

    @Override
    public boolean readBoolean() {
        byte b = currentByte();
        if (b == 't') {
            ensure(3);
            if (buffer[++currentIndex] == 'r'
                    && buffer[++currentIndex] == 'u'
                    && buffer[++currentIndex] == 'e') {
                return true;
            }
            throw createException("Expected value true");
        } else if (b == 'f') {
            ensure(4);
            if (buffer[++currentIndex] == 'a'
                    && buffer[++currentIndex] == 'l'
                    && buffer[++currentIndex] == 's'
                    && buffer[++currentIndex] == 'e') {
                return false;
            }
            throw createException("Expected value false");
        }
        throw createException("Expected boolean value", b);
    }

    @Override
    public byte readByte() {
        if (currentByte() == '-') {
            currentIndex++;
            return (byte) -parseByte(true);
        } else {
            return parseByte(false);
        }
    }

    @Override
    public short readShort() {
        if (currentByte() == '-') {
            currentIndex++;
            return (short) -parseShort(true);
        } else {
            return parseShort(false);
        }
    }

    @Override
    public int readInt() {
        if (currentByte() == '-') {
            currentIndex++;
            return -parseInt(true);
        } else {
            return parseInt(false);
        }
    }

    @Override
    public long readLong() {
        if (currentByte() == '-') {
            currentIndex++;
            return -parseLong(true);
        } else {
            return parseLong(false);
        }
    }

    @Override
    public float readFloat() {
        return (float) readDouble();
    }

    @Override
    public double readDouble() {
        int numberStart = currentIndex;
        int i = numberStart;

        boolean negative = false;
        byte b = buffer[i];
        if (b == '-') {
            negative = true;
            i++;
        } else if (b == '+') {
            i++;
        }
        b = buffer[i];
        if (b == 'N') {
            if (i + 2 < limit && buffer[i + 1] == 'a' && buffer[i + 2] == 'N') {
                currentIndex = i + 2;
                return Double.NaN;
            }
            throw createException("Invalid double number");
        } else if (b == 'I' || b == 'i') {
            if (i + 7 < limit
                    && buffer[i + 1] == 'n'
                    && buffer[i + 2] == 'f'
                    && buffer[i + 3] == 'i'
                    && buffer[i + 4] == 'n'
                    && buffer[i + 5] == 'i'
                    && buffer[i + 6] == 't'
                    && buffer[i + 7] == 'y') {
                currentIndex = i + 7;
                return negative ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
            }
            throw createException("Invalid double number");
        } else if (b < '0' || b > '9') {
            throw createException("Invalid double number");
        }

        long mantissa = 0;
        int digitsBeforeDecimal = 0;
        int significantDigits = 0;
        int leadingZerosAfterDecimal = 0;
        boolean hasDecimal = false;
        boolean foundNonZero = false;
        boolean delegateToJava = false;

        while (i < limit) {
            b = buffer[i];
            int digit = WHOLE_NUMBER_PARTS[b & 0xFF];
            if (digit > -1) {
                if (hasDecimal) {
                    if (!foundNonZero && digit == 0) {
                        leadingZerosAfterDecimal++;
                    } else {
                        foundNonZero = true;
                        if (significantDigits < 17) {
                            mantissa = mantissa * 10 + digit;
                            significantDigits++;
                        } else {
                            delegateToJava = true;
                            break;
                        }
                    }
                } else {
                    if (digit != 0 || foundNonZero) {
                        foundNonZero = true;
                        digitsBeforeDecimal++;
                        if (significantDigits < 17) {
                            mantissa = mantissa * 10 + digit;
                            significantDigits++;
                        } else {
                            delegateToJava = true;
                            break;
                        }
                    }
                }
                i++;
            } else if (b == '.') {
                if (hasDecimal) {
                    currentIndex = i;
                    throw createException("Multiple decimal separators detected");
                }
                hasDecimal = true;
                i++;
            } else {
                currentIndex = i - 1;
                break;
            }
        }
        if (delegateToJava) {
            currentIndex = i;
            skipNumber();
            return Double.parseDouble(new String(buffer, numberStart, currentIndex - numberStart + 1, StandardCharsets.UTF_8));
        }

        int decimalExponent = 0;
        if (digitsBeforeDecimal > 0) {
            decimalExponent = digitsBeforeDecimal - significantDigits;
        } else if (hasDecimal && foundNonZero) {
            decimalExponent = -(leadingZerosAfterDecimal + significantDigits);
        }

        int explicitExp = 0;
        b = i < limit ? buffer[i] : -1;
        if (b == 'e' || b == 'E') {
            i++;
            boolean expNegative = false;
            if (i < limit) {
                if (buffer[i] == '-') {
                    expNegative = true;
                    i++;
                } else if (buffer[i] == '+') {
                    i++;
                }
            } else {
                currentIndex = i - 1;
                throw createException("Missing exponent value");
            }

            int digit = -1;
            while (i < limit && (digit = WHOLE_NUMBER_PARTS[buffer[i] & 0xFF]) > -1) {
                explicitExp = explicitExp * 10 + digit;
                if (explicitExp > 1000) {
                    break;
                }
                i++;
            }
            currentIndex = i - 1;
            if (digit == -1 && i < limit) {
                b = buffer[i];
                if (b == 'e' || b == 'E' || b == '.') {
                    throw createException("Duplicit exponent or decimal point detected");
                }
            }
            decimalExponent += expNegative ? -explicitExp : explicitExp;
        }
        if (currentIndex == numberStart) {
            currentIndex = i;
        }

        if (mantissa == 0) {
            return negative ? -0.0 : 0.0;
        }

        if (decimalExponent >= POW10_DOUBLE_CACHE_SIZE || decimalExponent <= -POW10_DOUBLE_CACHE_SIZE) {
            skipNumber();
            return Double.parseDouble(new String(buffer, numberStart, currentIndex - numberStart + 1, StandardCharsets.UTF_8));
        }

        double result = mantissa;
        if (decimalExponent > 0) {
            result *= POW10_DOUBLE_CACHE[decimalExponent];
        } else if (decimalExponent < 0) {
            result /= POW10_DOUBLE_CACHE[-decimalExponent];
        }
        return negative ? -result : result;
    }

    @Override
    public BigInteger readBigInteger() {
        boolean inString = false;
        int numberStart = currentIndex;
        if (buffer[numberStart] == '"') {
            ensure(1);
            numberStart = ++currentIndex;
            inString = true;
        }
        skipNumber();
        int numberLength = currentIndex - numberStart + 1;
        BigInteger bigInteger = new BigInteger(new String(buffer, numberStart, numberLength, StandardCharsets.US_ASCII));
        if (inString) {
            ensure(1);
            if (buffer[++currentIndex] != '"') {
                throw createException("Expected the end of the string", buffer[currentIndex]);
            }
        }
        return bigInteger;
    }

    @Override
    public BigDecimal readBigDecimal() {
        boolean inString = false;
        if (buffer[currentIndex] == '"') {
            ensure(1);
            currentIndex++;
            inString = true;
        }
        BigDecimal bigDecimal = new BigDecimal(readNumberAsCharArray());
        if (inString) {
            ensure(1);
            if (buffer[++currentIndex] != '"') {
                throw createException("Expected the end of the string", buffer[currentIndex]);
            }
        }
        return bigDecimal;
    }

    @Override
    public byte[] readBinary() {
        if (currentByte() != '"') {
            throw createException("Binary data should be in a Base64 format and enclosed with double quotes", currentByte());
        }
        int binaryStart = currentIndex + 1;
        skipString();
        byte[] encoded = new byte[currentIndex - binaryStart];
        System.arraycopy(buffer, binaryStart, encoded, 0, encoded.length);
        return Base64.getDecoder().decode(encoded);
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
            throw createException("Unexpected value in JSON");
        }
        return false;
    }

    @Override
    public void skip() {
        switch (currentByte()) {
        case '"':
            skipString();
            return;
        case '{':
            skipObject();
            return;
        case '[':
            skipArray();
            return;
        case '-':
        case '+':
        case '.':
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
            return;
        case 't':
        case 'n':
            ensure(3);
            currentIndex += 3;
            return;
        case 'f':
            ensure(4);
            currentIndex += 4;
            return;
        case ',':
        case ':':
            return;
        default:
            throw createException("Invalid JSON value to skip", currentByte());
        }
    }

    @Override
    public void mark() {
        if (replayMarked) {
            throw new IllegalStateException("Parser has already been marked for replaying.");
        }
        replayMarked = true;
        mark = currentIndex;
        markedTapeIndex = currentTapeIndex;
    }

    @Override
    public void clearMark() {
        replayMarked = false;
        mark = -1;
        markedTapeIndex = -1;
    }

    @Override
    public void resetToMark() {
        if (!replayMarked) {
            throw new IllegalStateException("Parser tried to reset to the marked place, but no mark was found");
        }
        replayMarked = false;
        currentIndex = mark;
        currentTapeIndex = markedTapeIndex;
    }

    @Override
    public JsonException createException(String message) {
        clearMark();
        int errorStart = Math.max(currentIndex - 10, start);
        int errorLength = Math.min(currentIndex + 10, limit) - errorStart;
        int dataIndex = currentIndex - errorStart;
        BufferData bufferData = BufferData.create(buffer, errorStart, errorLength);
        return new JsonException(message + "\n"
                                         + "Error at JSON index: " + (currentIndex - start) + "\n"
                                         + "Data index: " + dataIndex + "\n"
                                         + "Data: \n"
                                         + bufferData.debugDataHex(false));
    }

    private static StructuralTape buildTape(byte[] input, int start, int length, int initialState) {
        Objects.requireNonNull(input, "input");
        Objects.checkFromIndexSize(start, length, input.length);

        if (length == 0) {
            return new StructuralTape(new int[0], 0, initialState);
        }

        int[] tape = new int[length];
        byte[] tailBuffer = null;
        int state = initialState;
        int chunkCount = (length + CHUNK_SIZE - 1) / CHUNK_SIZE;
        int tapeLength = 0;

        for (int chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
            int offset = start + chunkIndex * CHUNK_SIZE;
            int chunkLength = Math.min(CHUNK_SIZE, start + length - offset);
            if (chunkLength < CHUNK_SIZE && tailBuffer == null) {
                tailBuffer = new byte[CHUNK_SIZE];
            }
            long result = stage1ChunkAndAppend(tape, tapeLength, input, offset, chunkLength, state, tailBuffer, offset - start);
            tapeLength = unpackTapeLength(result);
            state = unpackState(result);
        }

        return new StructuralTape(tape, tapeLength, state);
    }

    private static long stage1ChunkAndAppend(int[] tape,
                                             int tapeLength,
                                             byte[] input,
                                             int offset,
                                             int length,
                                             int state,
                                             byte[] tailBuffer,
                                             int baseOffset) {
        Objects.requireNonNull(input, "input");
        Objects.checkFromIndexSize(offset, length, input.length);

        if (length < 0 || length > CHUNK_SIZE) {
            throw new IllegalArgumentException("Single-buffer stage 1 accepts 0.." + CHUNK_SIZE + " bytes, got " + length);
        }

        if (length == 0) {
            return packStage1Result(tapeLength, state);
        }

        long validMask = maskForLength(length);
        ByteVector chunk;
        if (length == CHUNK_SIZE) {
            chunk = ByteVector.fromArray(SPECIES_512, input, offset);
        } else {
            System.arraycopy(TAIL_PADDING, 0, tailBuffer, 0, CHUNK_SIZE);
            System.arraycopy(input, offset, tailBuffer, 0, length);
            chunk = ByteVector.fromArray(SPECIES_512, tailBuffer, 0);
        }

        long backslashes = chunk.eq((byte) '\\').toLong() & validMask;
        long quotes = chunk.eq((byte) '"').toLong() & validMask;
        boolean prevInString = hasState(state, STATE_IN_STRING);
        boolean prevOddBackslashRun = hasState(state, STATE_ODD_BACKSLASH_RUN);
        if (quotes == 0 && backslashes == 0) {
            if (prevInString) {
                boolean nextPseudoStructuralPredecessor = isWhitespaceByte(input[offset + length - 1]);
                return packStage1Result(tapeLength, packState(true, false, nextPseudoStructuralPredecessor));
            }

            VectorShuffle<Byte> lowNibble = chunk.and((byte) 0x0F).toShuffle();
            long whitespaces = chunk.eq(WHITESPACE_TABLE.rearrange(lowNibble)).toLong() & validMask;
            if (!prevInString && !prevOddBackslashRun) {
                long structurals = chunk.or((byte) 0x20).eq(STRUCTURAL_TABLE.rearrange(lowNibble)).toLong() & validMask;
                long pseudoStructuralPredecessors = structurals | whitespaces;
                boolean nextPseudoStructuralPredecessor = hasBit(pseudoStructuralPredecessors, length - 1);
                long shiftedPredecessors = (pseudoStructuralPredecessors << 1)
                        | (hasState(state, STATE_PSEUDO_STRUCTURAL_PREDECESSOR) ? 1L : 0L);
                long scalarStarts = shiftedPredecessors
                        & ~whitespaces
                        & ~structurals
                        & validMask;

                long remaining = structurals | scalarStarts;
                while (remaining != 0) {
                    int bitIndex = Long.numberOfTrailingZeros(remaining);
                    tape[tapeLength++] = baseOffset + bitIndex;
                    remaining &= remaining - 1;
                }

                return packStage1Result(tapeLength, packState(false, false, nextPseudoStructuralPredecessor));
            }
        }
        long escaped;
        boolean endsOddBackslashRun;
        if (backslashes == 0) {
            escaped = prevOddBackslashRun ? 1L : 0L;
            endsOddBackslashRun = false;
        } else {
            escaped = 0;
            boolean carryOdd = prevOddBackslashRun;
            if (carryOdd && (backslashes & 1L) == 0) {
                escaped = 1L;
                carryOdd = false;
            }

            long remaining = backslashes;
            boolean oddBackslashRunAtEnd = false;
            while (remaining != 0) {
                int runStart = Long.numberOfTrailingZeros(remaining);
                long shifted = remaining >>> runStart;
                int runLength = Long.numberOfTrailingZeros(~shifted);
                if (runLength == Long.SIZE) {
                    runLength = Long.SIZE - runStart;
                }

                boolean oddRun = (runLength & 1) != 0;
                if (carryOdd && runStart == 0) {
                    oddRun = !oddRun;
                    carryOdd = false;
                }

                int escapedIndex = runStart + runLength;
                if (oddRun) {
                    if (escapedIndex < length) {
                        escaped |= 1L << escapedIndex;
                    } else {
                        oddBackslashRunAtEnd = true;
                    }
                }

                long runMask = runLength == Long.SIZE
                        ? -1L
                        : ((1L << runLength) - 1L) << runStart;
                remaining &= ~runMask;
            }
            endsOddBackslashRun = oddBackslashRunAtEnd;
        }
        escaped &= validMask;

        long unescapedQuotes = quotes & ~escaped;

        long prevInStringMask = prevInString ? -1L : 0L;
        long stringRanges = (prefixXor(unescapedQuotes) ^ prevInStringMask) & validMask;
        VectorShuffle<Byte> lowNibble = chunk.and((byte) 0x0F).toShuffle();
        long whitespaces = chunk.eq(WHITESPACE_TABLE.rearrange(lowNibble)).toLong() & validMask;
        long structurals = chunk.or((byte) 0x20).eq(STRUCTURAL_TABLE.rearrange(lowNibble)).toLong() & validMask;
        long structuralsOutsideStrings = structurals & ~stringRanges;

        long openingQuotes = unescapedQuotes & stringRanges;
        long endingQuotes = unescapedQuotes & ~stringRanges;

        long pseudoStructuralPredecessors = structuralsOutsideStrings | whitespaces | endingQuotes;
        long shiftedPredecessors = (pseudoStructuralPredecessors << 1)
                | (hasState(state, STATE_PSEUDO_STRUCTURAL_PREDECESSOR) ? 1L : 0L);
        long scalarStarts = shiftedPredecessors
                & ~whitespaces
                & ~stringRanges
                & ~unescapedQuotes
                & ~structuralsOutsideStrings
                & validMask;

        long finalStructurals = structuralsOutsideStrings | openingQuotes | scalarStarts;
        long remaining = finalStructurals;
        while (remaining != 0) {
            int bitIndex = Long.numberOfTrailingZeros(remaining);
            tape[tapeLength++] = baseOffset + bitIndex;
            remaining &= remaining - 1;
        }

        boolean nextInString = prevInString ^ ((Long.bitCount(unescapedQuotes) & 1) != 0);
        boolean nextPseudoStructuralPredecessor = hasBit(pseudoStructuralPredecessors, length - 1);
        int nextState = packState(nextInString, endsOddBackslashRun, nextPseudoStructuralPredecessor);
        return packStage1Result(tapeLength, nextState);
    }

    private UnsupportedOperationException unsupported() {
        return new UnsupportedOperationException("SIMD parser stage 2 is not implemented yet");
    }

    private byte readNextByte() {
        return buffer[++currentIndex];
    }

    private void ensure(int amount) {
        if (currentIndex + amount >= limit) {
            throw createException("There is not enough data to be read. Incomplete JSON");
        }
    }

    private void skipString() {
        int index = currentIndex + 1;
        for (; index < limit; index++) {
            byte b = buffer[index];
            if (b == '"') {
                currentIndex = index;
                return;
            }
            if (b == '\\') {
                break;
            }
        }
        if (index >= limit) {
            throw createException("Unexpected end of string. Incomplete JSON or incorrect use of the skip method");
        }

        boolean escaped = false;
        for (; index < limit; index++) {
            byte b = buffer[index];
            if (b == '\\') {
                escaped = !escaped;
                continue;
            }
            if (b == '"' && !escaped) {
                currentIndex = index;
                return;
            }
            escaped = false;
        }
        throw createException("Unexpected end of string. Incomplete JSON or incorrect use of the skip method");
    }

    private void skipNumber() {
        for (int index = currentIndex; index < limit; index++) {
            byte b = buffer[index];
            if (!VALID_NUMBER_PARTS[b & 0xFF]) {
                currentIndex = index - 1;
                return;
            }
        }
        currentIndex = limit - 1;
    }

    private char processEscapedSequence() {
        if (!hasNext()) {
            throw createException("Error while processing an escaped string sequence. Incomplete JSON");
        }
        byte b = buffer[++currentIndex];
        if (expectLowSurrogate && b != 'u') {
            throw createException("Low surrogate must follow the high surrogate.", b);
        }
        switch (b) {
        case '\\':
        case '"':
        case '/':
            return (char) b;
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
                    (Parsers.translateHex(buffer[++currentIndex], this) << 12)
                            + (Parsers.translateHex(buffer[++currentIndex], this) << 8)
                            + (Parsers.translateHex(buffer[++currentIndex], this) << 4)
                            + Parsers.translateHex(buffer[++currentIndex], this));
            if (Character.isHighSurrogate(tmp)) {
                if (expectLowSurrogate) {
                    throw createException("A high surrogate must always be followed by a low surrogate");
                } else {
                    expectLowSurrogate = true;
                }
            } else if (Character.isLowSurrogate(tmp)) {
                if (expectLowSurrogate) {
                    expectLowSurrogate = false;
                } else {
                    throw createException("A low surrogate must always follow a high surrogate");
                }
            } else if (expectLowSurrogate) {
                throw createException("Low surrogate was expected to follow the high surrogate, but found "
                                              + Parsers.toPrintableForm(tmp));
            }
            return tmp;
        default:
            throw createException("Invalid escaped value", b);
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
                    throw createException("Invalid UTF-8 code point: " + Integer.toHexString(codePoint));
                }
                codePoint -= 0x10000;
                stringBuffer[position++] = (char) ((codePoint >> 10) + 0xD800);
                if (position == stringBufferLength) {
                    increaseStringBuffer();
                }
                stringBuffer[position++] = (char) ((codePoint & 0x3FF) + 0xDC00);
            } else {
                stringBuffer[position++] = (char) codePoint;
            }
        } else {
            throw createException("Invalid UTF-8 byte", currentByte);
        }
        return position;
    }

    private char decodeUtf8ToChar(byte currentByte) {
        if ((currentByte & 0xE0) == 0xC0) {
            int c2 = readNextByte() & 0x3F;
            int codePoint = ((currentByte & 0x1F) << 6) | c2;
            return (char) codePoint;
        } else if ((currentByte & 0xF0) == 0xE0) {
            ensure(2);
            int c2 = buffer[++currentIndex] & 0x3F;
            int c3 = buffer[++currentIndex] & 0x3F;
            int codePoint = ((currentByte & 0x0F) << 12) | (c2 << 6) | c3;
            return (char) codePoint;
        } else if ((currentByte & 0xF8) == 0xF0) {
            ensure(3);
            int c2 = buffer[++currentIndex] & 0x3F;
            int c3 = buffer[++currentIndex] & 0x3F;
            int c4 = buffer[++currentIndex] & 0x3F;
            int codePoint = ((currentByte & 0x07) << 18) | (c2 << 12) | (c3 << 6) | c4;
            if (codePoint >= 0x10000) {
                if (codePoint >= 0x110000) {
                    throw createException("Invalid UTF-8 code point: " + Integer.toHexString(codePoint));
                }
                throw createException("UTF-16 high and low surrogates cannot be represented as a single char");
            }
            return (char) codePoint;
        } else {
            throw createException("Invalid UTF-8 byte", currentByte);
        }
    }

    private void increaseStringBuffer() {
        increaseStringBuffer(stringBufferLength * 2);
    }

    private void increaseStringBuffer(int size) {
        stringBufferLength = size;
        char[] newBuf = new char[stringBufferLength];
        System.arraycopy(stringBuffer, 0, newBuf, 0, stringBuffer.length);
        stringBuffer = newBuf;
    }

    private char[] readNumberAsCharArray() {
        int readableBytes = limit - currentIndex;
        int firstRun = Math.min(stringBufferLength, readableBytes);
        stringBuffer[0] = (char) currentByte();
        int stringBufferIndex = 1;
        byte b;
        for (; stringBufferIndex < firstRun; stringBufferIndex++) {
            b = buffer[++currentIndex];
            if (!VALID_NUMBER_PARTS[b & 0xFF]) {
                currentIndex--;
                char[] chars = new char[stringBufferIndex];
                System.arraycopy(stringBuffer, 0, chars, 0, stringBufferIndex);
                return chars;
            }
            stringBuffer[stringBufferIndex] = (char) b;
        }
        if (stringBufferIndex == stringBufferLength) {
            increaseStringBuffer();
        }

        while (hasNext()) {
            b = readNextByte();
            if (!VALID_NUMBER_PARTS[b & 0xFF]) {
                currentIndex--;
                char[] chars = new char[stringBufferIndex];
                System.arraycopy(stringBuffer, 0, chars, 0, stringBufferIndex);
                return chars;
            }
            stringBuffer[stringBufferIndex++] = (char) b;
            if (stringBufferIndex == stringBufferLength) {
                increaseStringBuffer();
            }
        }
        char[] chars = new char[stringBufferIndex];
        System.arraycopy(stringBuffer, 0, chars, 0, stringBufferIndex);
        return chars;
    }

    private byte parseByte(boolean negative) {
        int digit1 = WHOLE_NUMBER_PARTS[currentByte() & 0xFF];
        if (digit1 < 0) {
            throw createException("Expected number", currentByte());
        }
        if (currentIndex + 4 < limit) {
            int digit2 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit2 < 0) {
                skipRemaining(digit2);
                return (byte) digit1;
            }
            int digit3 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            int possibleResult = digit1 * 10 + digit2;
            if (digit3 < 0) {
                skipRemaining(digit3);
                return (byte) possibleResult;
            }
            int digit4 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit4 < 0) {
                skipRemaining(digit4);
                if (negative) {
                    if (-possibleResult > -BYTE_SIZE_BORDER || (-possibleResult == -BYTE_SIZE_BORDER && digit3 <= 8)) {
                        return (byte) (possibleResult * 10 + digit3);
                    }
                } else if (possibleResult < BYTE_SIZE_BORDER || (possibleResult == BYTE_SIZE_BORDER && digit3 <= 7)) {
                    return (byte) (possibleResult * 10 + digit3);
                }
            }
            throw createException("The number is too big for a byte value");
        }
        boolean hasNext = hasNext();
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit2 < 0) {
            if (hasNext) {
                skipRemaining(digit2);
            }
            return (byte) digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        int possibleResult = digit1 * 10 + digit2;
        if (digit3 < 0) {
            if (hasNext) {
                skipRemaining(digit3);
            }
            return (byte) possibleResult;
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit4 < 0) {
            if (hasNext) {
                skipRemaining(digit4);
            }
            if (negative) {
                if (-possibleResult > -BYTE_SIZE_BORDER || (-possibleResult == -BYTE_SIZE_BORDER && digit3 <= 8)) {
                    return (byte) (possibleResult * 10 + digit3);
                }
            } else if (possibleResult < BYTE_SIZE_BORDER || (possibleResult == BYTE_SIZE_BORDER && digit3 <= 7)) {
                return (byte) (possibleResult * 10 + digit3);
            }
        }
        throw createException("The number is too big for a byte value");
    }

    private short parseShort(boolean negative) {
        int digit1 = WHOLE_NUMBER_PARTS[currentByte() & 0xFF];
        if (digit1 < 0) {
            throw createException("Expected number", currentByte());
        }
        if (currentIndex + 6 < limit) {
            int digit2 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit2 < 0) {
                skipRemaining(digit2);
                return (short) digit1;
            }
            int digit3 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit3 < 0) {
                skipRemaining(digit3);
                return (short) (digit1 * 10 + digit2);
            }
            int digit4 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit4 < 0) {
                skipRemaining(digit4);
                return (short) (digit1 * 100 + digit2 * 10 + digit3);
            }
            int digit5 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            short possibleResult = (short) (digit1 * 1000 + digit2 * 100 + digit3 * 10 + digit4);
            if (digit5 < 0) {
                skipRemaining(digit5);
                return possibleResult;
            }
            int digit6 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
            if (digit6 < 0) {
                skipRemaining(digit6);
                if (negative) {
                    if (-possibleResult > -SHORT_SIZE_BORDER || (-possibleResult == -SHORT_SIZE_BORDER && digit5 <= 8)) {
                        return (short) (possibleResult * 10 + digit5);
                    }
                } else if (possibleResult < SHORT_SIZE_BORDER || (possibleResult == SHORT_SIZE_BORDER && digit5 <= 7)) {
                    return (short) (possibleResult * 10 + digit5);
                }
            }
            throw createException("The number is too big for a short value");
        }
        boolean hasNext = hasNext();
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit2 < 0) {
            if (hasNext) {
                skipRemaining(digit2);
            }
            return (short) digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit3 < 0) {
            if (hasNext) {
                skipRemaining(digit3);
            }
            return (short) (digit1 * 10 + digit2);
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit4 < 0) {
            if (hasNext) {
                skipRemaining(digit4);
            }
            return (short) (digit1 * 100 + digit2 * 10 + digit3);
        }
        hasNext = hasNext();
        int digit5 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        short possibleResult = (short) (digit1 * 1000 + digit2 * 100 + digit3 * 10 + digit4);
        if (digit5 < 0) {
            if (hasNext) {
                skipRemaining(digit5);
            }
            return possibleResult;
        }
        hasNext = hasNext();
        int digit6 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit6 < 0) {
            if (hasNext) {
                skipRemaining(digit6);
            }
            if (negative) {
                if (-possibleResult > -SHORT_SIZE_BORDER || (-possibleResult == -SHORT_SIZE_BORDER && digit5 <= 8)) {
                    return (short) (possibleResult * 10 + digit5);
                }
            } else if (possibleResult < SHORT_SIZE_BORDER || (possibleResult == SHORT_SIZE_BORDER && digit5 <= 7)) {
                return (short) (possibleResult * 10 + digit5);
            }
        }
        throw createException("The number is too big for a short value");
    }

    private int parseInt(boolean negative) {
        if (currentIndex + 11 < limit) {
            return parseIntFast(negative);
        }
        int digit1 = WHOLE_NUMBER_PARTS[currentByte() & 0xFF];
        if (digit1 < 0) {
            throw createException("Expected number", currentByte());
        }
        boolean hasNext = hasNext();
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit2 < 0) {
            if (hasNext) {
                skipRemaining(digit2);
            }
            return digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit3 < 0) {
            if (hasNext) {
                skipRemaining(digit3);
            }
            return digit1 * 10 + digit2;
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit4 < 0) {
            if (hasNext) {
                skipRemaining(digit4);
            }
            return digit1 * 100 + digit2 * 10 + digit3;
        }
        hasNext = hasNext();
        int digit5 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit5 < 0) {
            if (hasNext) {
                skipRemaining(digit5);
            }
            return digit1 * 1000 + digit2 * 100 + digit3 * 10 + digit4;
        }
        hasNext = hasNext();
        int digit6 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit6 < 0) {
            if (hasNext) {
                skipRemaining(digit6);
            }
            return digit1 * 10000 + digit2 * 1000 + digit3 * 100 + digit4 * 10 + digit5;
        }
        hasNext = hasNext();
        int digit7 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit7 < 0) {
            if (hasNext) {
                skipRemaining(digit7);
            }
            return digit1 * 100000 + digit2 * 10000 + digit3 * 1000 + digit4 * 100 + digit5 * 10 + digit6;
        }
        hasNext = hasNext();
        int digit8 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit8 < 0) {
            if (hasNext) {
                skipRemaining(digit8);
            }
            return digit1 * 1000000 + digit2 * 100000 + digit3 * 10000 + digit4 * 1000 + digit5 * 100 + digit6 * 10 + digit7;
        }
        hasNext = hasNext();
        int digit9 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit9 < 0) {
            if (hasNext) {
                skipRemaining(digit9);
            }
            return digit1 * 10000000 + digit2 * 1000000 + digit3 * 100000 + digit4 * 10000 + digit5 * 1000 + digit6 * 100
                    + digit7 * 10 + digit8;
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
        if (digit10 < 0) {
            if (hasNext) {
                skipRemaining(digit10);
            }
            return possibleResult;
        }
        hasNext = hasNext();
        int digit11 = hasNext ? WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF] : -1;
        if (digit11 < 0) {
            if (hasNext) {
                skipRemaining(digit11);
            }
            if (negative) {
                if (-possibleResult > -INT_SIZE_BORDER || (-possibleResult == -INT_SIZE_BORDER && digit10 <= 8)) {
                    return possibleResult * 10 + digit10;
                }
            } else if (possibleResult < INT_SIZE_BORDER || (possibleResult == INT_SIZE_BORDER && digit10 <= 7)) {
                return possibleResult * 10 + digit10;
            }
        }
        throw createException("The number is too big for an int value");
    }

    private int parseIntFast(boolean negative) {
        int digit1 = WHOLE_NUMBER_PARTS[currentByte() & 0xFF];
        if (digit1 < 0) {
            throw createException("Expected number", currentByte());
        }
        int digit2 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit2 < 0) {
            skipRemaining(digit2);
            return digit1;
        }
        int digit3 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit3 < 0) {
            skipRemaining(digit3);
            return digit1 * 10 + digit2;
        }
        int digit4 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit4 < 0) {
            skipRemaining(digit4);
            return digit1 * 100 + digit2 * 10 + digit3;
        }
        int digit5 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit5 < 0) {
            skipRemaining(digit5);
            return digit1 * 1000 + digit2 * 100 + digit3 * 10 + digit4;
        }
        int digit6 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit6 < 0) {
            skipRemaining(digit6);
            return digit1 * 10000 + digit2 * 1000 + digit3 * 100 + digit4 * 10 + digit5;
        }
        int digit7 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit7 < 0) {
            skipRemaining(digit7);
            return digit1 * 100000 + digit2 * 10000 + digit3 * 1000 + digit4 * 100 + digit5 * 10 + digit6;
        }
        int digit8 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit8 < 0) {
            skipRemaining(digit8);
            return digit1 * 1000000 + digit2 * 100000 + digit3 * 10000 + digit4 * 1000 + digit5 * 100 + digit6 * 10 + digit7;
        }
        int digit9 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit9 < 0) {
            skipRemaining(digit9);
            return digit1 * 10000000 + digit2 * 1000000 + digit3 * 100000 + digit4 * 10000 + digit5 * 1000 + digit6 * 100
                    + digit7 * 10 + digit8;
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
        if (digit10 < 0) {
            skipRemaining(digit10);
            return possibleResult;
        }
        int digit11 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit11 < 0) {
            skipRemaining(digit11);
            if (negative) {
                if (-possibleResult > -INT_SIZE_BORDER || (-possibleResult == -INT_SIZE_BORDER && digit10 <= 8)) {
                    return possibleResult * 10 + digit10;
                }
            } else if (possibleResult < INT_SIZE_BORDER || (possibleResult == INT_SIZE_BORDER && digit10 <= 7)) {
                return possibleResult * 10 + digit10;
            }
        }
        throw createException("The number is too big for an int value");
    }

    @SuppressWarnings("checkstyle:MethodLength")
    private long parseLong(boolean negative) {
        if (currentIndex + 19 < limit) {
            return parseLongFast(negative);
        }
        boolean hasNext = hasNext();
        int digit1 = WHOLE_NUMBER_PARTS[currentByte()];
        if (digit1 < 0) {
            throw createException("Expected number", currentByte());
        }
        int digit2 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit2 < 0) {
            if (hasNext) {
                skipRemaining(digit2);
            }
            return digit1;
        }
        hasNext = hasNext();
        int digit3 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit3 < 0) {
            if (hasNext) {
                skipRemaining(digit3);
            }
            return digit1 * 10L + digit2;
        }
        hasNext = hasNext();
        int digit4 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit4 < 0) {
            if (hasNext) {
                skipRemaining(digit4);
            }
            return digit1 * 100L + digit2 * 10L + digit3;
        }
        hasNext = hasNext();
        int digit5 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit5 < 0) {
            if (hasNext) {
                skipRemaining(digit5);
            }
            return digit1 * 1000L + digit2 * 100L + digit3 * 10L + digit4;
        }
        hasNext = hasNext();
        int digit6 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit6 < 0) {
            if (hasNext) {
                skipRemaining(digit6);
            }
            return digit1 * 10000L + digit2 * 1000L + digit3 * 100L + digit4 * 10L + digit5;
        }
        hasNext = hasNext();
        int digit7 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit7 < 0) {
            if (hasNext) {
                skipRemaining(digit7);
            }
            return digit1 * 100000L + digit2 * 10000L + digit3 * 1000L + digit4 * 100L + digit5 * 10L + digit6;
        }
        hasNext = hasNext();
        int digit8 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit8 < 0) {
            if (hasNext) {
                skipRemaining(digit8);
            }
            return digit1 * 1000000L + digit2 * 100000L + digit3 * 10000L + digit4 * 1000L + digit5 * 100L + digit6 * 10L + digit7;
        }
        hasNext = hasNext();
        int digit9 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit9 < 0) {
            if (hasNext) {
                skipRemaining(digit9);
            }
            return digit1 * 10000000L + digit2 * 1000000L + digit3 * 100000L + digit4 * 10000L + digit5 * 1000L + digit6 * 100L
                    + digit7 * 10L + digit8;
        }
        hasNext = hasNext();
        int digit10 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit10 < 0) {
            if (hasNext) {
                skipRemaining(digit10);
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
        int digit11 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit11 < 0) {
            if (hasNext) {
                skipRemaining(digit11);
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
        int digit12 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit12 < 0) {
            if (hasNext) {
                skipRemaining(digit12);
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
        int digit13 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit13 < 0) {
            if (hasNext) {
                skipRemaining(digit13);
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
        int digit14 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit14 < 0) {
            if (hasNext) {
                skipRemaining(digit14);
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
        int digit15 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit15 < 0) {
            if (hasNext) {
                skipRemaining(digit15);
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
        int digit16 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit16 < 0) {
            if (hasNext) {
                skipRemaining(digit16);
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
        int digit17 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit17 < 0) {
            if (hasNext) {
                skipRemaining(digit17);
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
        int digit18 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit18 < 0) {
            if (hasNext) {
                skipRemaining(digit18);
            }
            return digit1 * 10000000000000000L
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
        }
        hasNext = hasNext();
        int digit19 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        long possibleResult = digit1 * 100000000000000000L
                + digit2 * 10000000000000000L
                + digit3 * 1000000000000000L
                + digit4 * 100000000000000L
                + digit5 * 10000000000000L
                + digit6 * 1000000000000L
                + digit7 * 100000000000L
                + digit8 * 10000000000L
                + digit9 * 1000000000L
                + digit10 * 100000000L
                + digit11 * 10000000L
                + digit12 * 1000000L
                + digit13 * 100000L
                + digit14 * 10000L
                + digit15 * 1000L
                + digit16 * 100L
                + digit17 * 10L
                + digit18;
        if (digit19 < 0) {
            if (hasNext) {
                skipRemaining(digit19);
            }
            return possibleResult;
        }
        hasNext = hasNext();
        int digit20 = hasNext ? WHOLE_NUMBER_PARTS[readNextByte() & 0xFF] : -1;
        if (digit20 < 0) {
            if (hasNext) {
                skipRemaining(digit20);
            }
            if (negative) {
                if (-possibleResult > -LONG_SIZE_BORDER || (-possibleResult == -LONG_SIZE_BORDER && digit19 <= 8)) {
                    return possibleResult * 10 + digit19;
                }
            } else if (possibleResult < LONG_SIZE_BORDER || (possibleResult == LONG_SIZE_BORDER && digit19 <= 7)) {
                return possibleResult * 10 + digit19;
            }
        }
        throw createException("The number is too big for a long value");
    }

    @SuppressWarnings("checkstyle:MethodLength")
    private long parseLongFast(boolean negative) {
        int digit1 = WHOLE_NUMBER_PARTS[currentByte()];
        if (digit1 < 0) {
            throw createException("Expected number", currentByte());
        }
        int digit2 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit2 < 0) {
            skipRemaining(digit2);
            return digit1;
        }
        int digit3 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit3 < 0) {
            skipRemaining(digit3);
            return digit1 * 10L + digit2;
        }
        int digit4 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit4 < 0) {
            skipRemaining(digit4);
            return digit1 * 100L + digit2 * 10L + digit3;
        }
        int digit5 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit5 < 0) {
            skipRemaining(digit5);
            return digit1 * 1000L + digit2 * 100L + digit3 * 10L + digit4;
        }
        int digit6 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit6 < 0) {
            skipRemaining(digit6);
            return digit1 * 10000L + digit2 * 1000L + digit3 * 100L + digit4 * 10L + digit5;
        }
        int digit7 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit7 < 0) {
            skipRemaining(digit7);
            return digit1 * 100000L + digit2 * 10000L + digit3 * 1000L + digit4 * 100L + digit5 * 10L + digit6;
        }
        int digit8 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit8 < 0) {
            skipRemaining(digit8);
            return digit1 * 1000000L + digit2 * 100000L + digit3 * 10000L + digit4 * 1000L + digit5 * 100L + digit6 * 10L + digit7;
        }
        int digit9 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit9 < 0) {
            skipRemaining(digit9);
            return digit1 * 10000000L + digit2 * 1000000L + digit3 * 100000L + digit4 * 10000L + digit5 * 1000L + digit6 * 100L
                    + digit7 * 10L + digit8;
        }
        int digit10 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit10 < 0) {
            skipRemaining(digit10);
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
        if (digit11 < 0) {
            skipRemaining(digit11);
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
        if (digit12 < 0) {
            skipRemaining(digit12);
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
        if (digit13 < 0) {
            skipRemaining(digit13);
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
        if (digit14 < 0) {
            skipRemaining(digit14);
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
        if (digit15 < 0) {
            skipRemaining(digit15);
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
        if (digit16 < 0) {
            skipRemaining(digit16);
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
        if (digit17 < 0) {
            skipRemaining(digit17);
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
        if (digit18 < 0) {
            skipRemaining(digit18);
            return digit1 * 10000000000000000L
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
        }
        int digit19 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        long possibleResult = digit1 * 100000000000000000L
                + digit2 * 10000000000000000L
                + digit3 * 1000000000000000L
                + digit4 * 100000000000000L
                + digit5 * 10000000000000L
                + digit6 * 1000000000000L
                + digit7 * 100000000000L
                + digit8 * 10000000000L
                + digit9 * 1000000000L
                + digit10 * 100000000L
                + digit11 * 10000000L
                + digit12 * 1000000L
                + digit13 * 100000L
                + digit14 * 10000L
                + digit15 * 1000L
                + digit16 * 100L
                + digit17 * 10L
                + digit18;
        if (digit19 < 0) {
            skipRemaining(digit19);
            return possibleResult;
        }
        int digit20 = WHOLE_NUMBER_PARTS[buffer[++currentIndex] & 0xFF];
        if (digit20 < 0) {
            skipRemaining(digit20);
            if (negative) {
                if (-possibleResult > -LONG_SIZE_BORDER || (-possibleResult == -LONG_SIZE_BORDER && digit19 <= 8)) {
                    return possibleResult * 10 + digit19;
                }
            } else if (possibleResult < LONG_SIZE_BORDER || (possibleResult == LONG_SIZE_BORDER && digit19 <= 7)) {
                return possibleResult * 10 + digit19;
            }
        }
        throw createException("The number is too big for a long value");
    }

    private void skipRemaining(int mark) {
        if (mark == DOT_MARK) {
            skipNumber();
        } else {
            currentIndex--;
        }
    }

    private void skipObject() {
        byte b = nextToken();
        if (b == '}') {
            return;
        }
        if (b != '"') {
            throw createException("Key name start expected", b);
        }
        skipString();
        b = nextToken();
        if (b != ':') {
            throw createException("Colon expected after the key", b);
        }
        nextToken();
        skip();
        b = nextToken();
        while (b == ',') {
            b = nextToken();
            if (b != '"') {
                throw createException("Key name start expected", b);
            }
            skipString();
            b = nextToken();
            if (b != ':') {
                throw createException("Colon expected after the key", b);
            }
            nextToken();
            skip();
            b = nextToken();
        }
        if (b != '}') {
            throw createException("Comma or the end of the object expected", b);
        }
    }

    private void skipArray() {
        byte b = nextToken();
        if (b == ']') {
            return;
        }
        skip();
        b = nextToken();
        while (b == ',') {
            nextToken();
            skip();
            b = nextToken();
        }
        if (b != ']') {
            throw createException("Comma or the end of the array expected", b);
        }
    }

    private static byte[] tile(byte[] src16) {
        int copies = SPECIES_512.vectorByteSize() / 16;
        byte[] dst = new byte[SPECIES_512.vectorByteSize()];
        for (int i = 0; i < copies; i++) {
            System.arraycopy(src16, 0, dst, i * 16, 16);
        }
        return dst;
    }

    private static long maskForLength(int length) {
        if (length == 0) {
            return 0;
        }
        if (length == Long.SIZE) {
            return -1L;
        }
        return (1L << length) - 1;
    }

    private static boolean hasBit(long mask, int index) {
        return index >= 0 && ((mask >>> index) & 1L) != 0;
    }

    private static boolean isWhitespaceByte(byte b) {
        return b == ' ' || b == '\t' || b == '\n' || b == '\r';
    }

    private static long prefixXor(long bitmask) {
        bitmask ^= bitmask << 1;
        bitmask ^= bitmask << 2;
        bitmask ^= bitmask << 4;
        bitmask ^= bitmask << 8;
        bitmask ^= bitmask << 16;
        bitmask ^= bitmask << 32;
        return bitmask;
    }

    private static boolean hasState(int state, int flag) {
        return (state & flag) != 0;
    }

    private static int packState(boolean inString, boolean oddBackslashRun, boolean pseudoStructuralPredecessor) {
        int state = 0;
        if (inString) {
            state |= STATE_IN_STRING;
        }
        if (oddBackslashRun) {
            state |= STATE_ODD_BACKSLASH_RUN;
        }
        if (pseudoStructuralPredecessor) {
            state |= STATE_PSEUDO_STRUCTURAL_PREDECESSOR;
        }
        return state;
    }

    private static long packStage1Result(int tapeLength, int state) {
        return (((long) tapeLength) << 32) | (state & 0xFFFF_FFFFL);
    }

    private static int unpackTapeLength(long result) {
        return (int) (result >>> 32);
    }

    private static int unpackState(long result) {
        return (int) result;
    }

    private record StructuralTape(int[] tape,
                                  int tapeLength,
                                  int nextState) {
    }
}
