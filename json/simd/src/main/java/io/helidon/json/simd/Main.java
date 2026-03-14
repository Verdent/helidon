package io.helidon.json.simd;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.VectorShuffle;

import static jdk.incubator.vector.ByteVector.SPECIES_512;

public final class Main {

    public static final int CHUNK_SIZE = SPECIES_512.vectorByteSize();

    public static final Stage1State INITIAL_STATE = new Stage1State(false, false, true);

    private static final ByteVector WHITESPACE_TABLE;
    private static final ByteVector STRUCTURAL_TABLE;

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
    }

    private Main() {
    }

    public record Stage1State(boolean prevInString,
                              boolean prevOddBackslashRun,
                              boolean prevPseudoStructuralPredecessor) {
    }

    public record Stage1Result(long structurals,
                               long openingQuotes,
                               long scalarStarts,
                               long structuralsOutsideStrings,
                               long whitespaces,
                               long unescapedQuotes,
                               long escaped,
                               long stringRanges,
                               Stage1State nextState) {
    }

    public record StructuralTape(int[] tape,
                                 Stage1State nextState) {
    }

    public static StructuralTape stage1(byte[] input) {
        return stage1(input, INITIAL_STATE);
    }

    public static StructuralTape stage1(byte[] input, Stage1State initialState) {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(initialState, "initialState");

        if (input.length == 0) {
            return new StructuralTape(new int[0], initialState);
        }

        int chunkCount = (input.length + CHUNK_SIZE - 1) / CHUNK_SIZE;
        IntCollector indexes = new IntCollector(input.length);
        Stage1State state = initialState;

        for (int chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
            int offset = chunkIndex * CHUNK_SIZE;
            int chunkLength = Math.min(CHUNK_SIZE, input.length - offset);
            Stage1Result result = stage1(input, offset, chunkLength, state);
            appendIndexes(indexes, result.structurals(), offset);
            state = result.nextState();
        }

        return new StructuralTape(indexes.toArray(), state);
    }

    public static Stage1Result stage1(byte[] input, int offset, int length, Stage1State state) {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(state, "state");
        Objects.checkFromIndexSize(offset, length, input.length);

        if (length < 0 || length > CHUNK_SIZE) {
            throw new IllegalArgumentException("Single-buffer stage 1 accepts 0.." + CHUNK_SIZE + " bytes, got " + length);
        }

        if (length == 0) {
            return new Stage1Result(0, 0, 0, 0, 0, 0, 0, 0, state);
        }

        byte[] block = new byte[CHUNK_SIZE];
        System.arraycopy(input, offset, block, 0, length);

        long validMask = maskForLength(length);
        ByteVector chunk = ByteVector.fromArray(SPECIES_512, block, 0);

        long identifiedBackslashes = chunk.eq((byte) '\\').toLong() & validMask;
        EscapeInfo escapeInfo = computeEscapedPositions(block, length, state.prevOddBackslashRun());
        long escaped = escapeInfo.escaped() & validMask;

        long quotes = chunk.eq((byte) '"').toLong() & validMask;
        long unescapedQuotes = quotes & ~escaped;

        long prevInStringMask = state.prevInString() ? -1L : 0L;
        long stringRanges = (prefixXor(unescapedQuotes) ^ prevInStringMask) & validMask;

        VectorShuffle<Byte> lowNibble = chunk.and((byte) 0x0F).toShuffle();
        long whitespaces = chunk.eq(WHITESPACE_TABLE.rearrange(lowNibble)).toLong() & validMask;
        long structurals = chunk.or((byte) 0x20).eq(STRUCTURAL_TABLE.rearrange(lowNibble)).toLong() & validMask;
        long structuralsOutsideStrings = structurals & ~stringRanges;

        long openingQuotes = unescapedQuotes & stringRanges;
        long endingQuotes = unescapedQuotes & ~stringRanges;

        long pseudoStructuralPredecessors = structuralsOutsideStrings | whitespaces | endingQuotes;
        long shiftedPredecessors = (pseudoStructuralPredecessors << 1)
                | (state.prevPseudoStructuralPredecessor() ? 1L : 0L);
        long scalarStarts = shiftedPredecessors
                & ~whitespaces
                & ~stringRanges
                & ~unescapedQuotes
                & ~structuralsOutsideStrings
                & validMask;

        long finalStructurals = structuralsOutsideStrings | openingQuotes | scalarStarts;

        boolean nextInString = state.prevInString() ^ ((Long.bitCount(unescapedQuotes) & 1) != 0);
        boolean nextPseudoStructuralPredecessor =
                hasBit(pseudoStructuralPredecessors, length - 1);

        Stage1State nextState = new Stage1State(
                nextInString,
                escapeInfo.endsOddBackslashRun(),
                nextPseudoStructuralPredecessor
        );

        return new Stage1Result(
                finalStructurals,
                openingQuotes,
                scalarStarts,
                structuralsOutsideStrings,
                whitespaces,
                unescapedQuotes,
                escaped,
                stringRanges,
                nextState
        );
    }

    public static void main(String[] args) {
        String json = args.length == 0
                ? "{ \"Ahoj-k,amo\": [ 116,\"te sticek\" , 234 , \"true\", false ], \"testickovej\" }"
                : args[0];
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        StructuralTape result = stage1(bytes);

        System.out.println("json:        " + json);
        System.out.println("tape:        " + Arrays.toString(result.tape()));
        System.out.println("next state:  " + result.nextState());
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

    private static void appendIndexes(IntCollector indexes, long structurals, int baseOffset) {
        long remaining = structurals;
        while (remaining != 0) {
            int bitIndex = Long.numberOfTrailingZeros(remaining);
            indexes.add(baseOffset + bitIndex);
            remaining &= remaining - 1;
        }
    }

    private static EscapeInfo computeEscapedPositions(byte[] block, int length, boolean prevOddBackslashRun) {
        int runLength = prevOddBackslashRun ? 1 : 0;
        long escaped = 0;

        for (int i = 0; i < length; i++) {
            if (block[i] == '\\') {
                runLength++;
                continue;
            }
            if ((runLength & 1) != 0) {
                escaped |= 1L << i;
            }
            runLength = 0;
        }

        return new EscapeInfo(escaped, (runLength & 1) != 0);
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

    public static String binary(long value) {
        StringBuilder sb = new StringBuilder(Long.SIZE);
        for (int i = 0; i < Long.SIZE; i++) {
            sb.append((value & 1L) == 1L ? '1' : '0');
            value >>>= 1;
        }
        return sb.toString();
    }

    private record EscapeInfo(long escaped, boolean endsOddBackslashRun) {
    }

    private static final class IntCollector {
        private int[] values;
        private int size;

        private IntCollector(int initialCapacity) {
            this.values = new int[Math.max(4, initialCapacity)];
        }

        private void add(int value) {
            if (size == values.length) {
                values = Arrays.copyOf(values, values.length * 2);
            }
            values[size++] = value;
        }

        private int[] toArray() {
            return Arrays.copyOf(values, size);
        }
    }
}
