package io.helidon.json;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.VectorMask;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorShuffle;

import static jdk.incubator.vector.ByteVector.SPECIES_256;
import static jdk.incubator.vector.ByteVector.SPECIES_512;

/**
 * Main30 plus a quote-free scalar classification fast path.
 */
public final class Main34 {

    private static final int VECTOR_BIT_SIZE = VectorUtils.BYTE_SPECIES.vectorBitSize();
    private static final int BLOCK_SIZE = 64;
    private static final int HALF_BLOCK_BITS = SPECIES_256.vectorByteSize();
    private static final byte BACKSLASH = (byte) '\\';
    private static final byte QUOTE = (byte) '"';
    private static final byte LAST_CONTROL_CHARACTER = (byte) 0x1F;
    private static final VectorOperators.Comparison UNSIGNED_LE_COMPARISON = unsignedLeComparison();
    private static final long EVEN_BITS_MASK = 0x5555555555555555L;
    private static final long ODD_BITS_MASK = ~EVEN_BITS_MASK;
    private static final byte LOW_NIBBLE_MASK = 0x0f;
    private static final ByteVector WHITESPACE_TABLE = VectorUtils.repeat(
            new byte[]{' ', 100, 100, 100, 17, 100, 113, 2, 100, '\t', '\n', 112, 100, '\r', 100, 100}
    );
    private static final ByteVector OP_TABLE = VectorUtils.repeat(
            new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ':', '{', ',', '}', 0, 0}
    );
    private static final int DEAD_WRITE_SLACK = 16;

    private static final IndexImplementation IMPLEMENTATION = switch (VECTOR_BIT_SIZE) {
        case 256 -> new Index256();
        case 512 -> new Index512();
        default -> throw new UnsupportedOperationException("Unsupported vector width: " + VECTOR_BIT_SIZE);
    };

    private Main34() {
    }

    public static int createTape(byte[] input, Workspace workspace) {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(workspace, "workspace");
        if (input.length == 0) {
            return 0;
        }
        workspace.ensureCapacity(input.length + DEAD_WRITE_SLACK);
        return IMPLEMENTATION.createTape(input, workspace);
    }

    public static Workspace newWorkspace() {
        return new Workspace();
    }

    public static String implementationName() {
        return IMPLEMENTATION.name();
    }

    public static void main(String[] args) {
        String json = args.length == 0
                ? "{\"name\":\"simdjson\",\"values\":[1,2,3],\"escaped\":\"\\\\\\\"\",\"ok\":true}".repeat(2)
                : args[0];
        Workspace workspace = newWorkspace();
        int length = createTape(json.getBytes(StandardCharsets.UTF_8), workspace);

        System.out.println("Implementation: " + implementationName());
        System.out.println("Tape length: " + length);
        System.out.print("Tape: ");
        for (int i = 0; i < length; i++) {
            if (i != 0) {
                System.out.print(", ");
            }
            System.out.print(workspace.values()[i]);
        }
        System.out.println();
    }

    public static final class Workspace {
        private int[] values = new int[0];

        public int[] values() {
            return values;
        }

        private void ensureCapacity(int needed) {
            if (values.length < needed) {
                values = new int[needed];
            }
        }
    }

    private interface IndexImplementation {
        int createTape(byte[] input, Workspace workspace);

        String name();
    }

    private static final class Index256 implements IndexImplementation {
        @Override
        public int createTape(byte[] input, Workspace workspace) {
            int[] tape = workspace.values;
            int tapeLength = 0;
            long prevInString = 0;
            long prevEscaped = 0;
            long prevStructurals = 0;
            long unescapedCharsError = 0;
            long prevScalar = 0;

            int loopBound = SPECIES_512.loopBound(input.length);
            int offset = 0;
            int blockIndex = 0;
            for (; offset < loopBound; offset += BLOCK_SIZE) {
                ByteVector chunk0 = ByteVector.fromArray(SPECIES_256, input, offset);
                ByteVector chunk1 = ByteVector.fromArray(SPECIES_256, input, offset + 32);

                long backslash0 = chunk0.eq(BACKSLASH).toLong();
                long backslash1 = chunk1.eq(BACKSLASH).toLong();
                long backslash = backslash0 | (backslash1 << HALF_BLOCK_BITS);

                long rawQuote0 = chunk0.eq(QUOTE).toLong();
                long rawQuote1 = chunk1.eq(QUOTE).toLong();
                long rawQuote = rawQuote0 | (rawQuote1 << HALF_BLOCK_BITS);

                long quote;
                if (rawQuote == 0) {
                    prevEscaped = backslash == 0 ? 0 : endsWithOddBackslashRun(backslash, BLOCK_SIZE, prevEscaped != 0) ? 1 : 0;
                    quote = 0;
                } else {
                    long escaped;
                    if (backslash == 0) {
                        escaped = prevEscaped;
                        prevEscaped = 0;
                    } else {
                        backslash &= ~prevEscaped;
                        long followsEscape = (backslash << 1) | prevEscaped;
                        long oddSequenceStarts = backslash & ODD_BITS_MASK & ~followsEscape;
                        long sequencesStartingOnEvenBits = oddSequenceStarts + backslash;
                        prevEscaped = ((oddSequenceStarts >>> 1)
                                + (backslash >>> 1)
                                + ((oddSequenceStarts & backslash) & 1)) >>> 63;
                        long invertMask = sequencesStartingOnEvenBits << 1;
                        escaped = (EVEN_BITS_MASK ^ invertMask) & followsEscape;
                    }
                    quote = rawQuote & ~escaped;
                }

                VectorShuffle<Byte> chunk0Low = chunk0.and(LOW_NIBBLE_MASK).toShuffle();
                VectorShuffle<Byte> chunk1Low = chunk1.and(LOW_NIBBLE_MASK).toShuffle();

                long whitespace0 = chunk0.eq(WHITESPACE_TABLE.rearrange(chunk0Low)).toLong();
                long whitespace1 = chunk1.eq(WHITESPACE_TABLE.rearrange(chunk1Low)).toLong();
                long whitespace = whitespace0 | (whitespace1 << HALF_BLOCK_BITS);

                ByteVector curlified0 = chunk0.or((byte) 0x20);
                ByteVector curlified1 = chunk1.or((byte) 0x20);
                long op0 = curlified0.eq(OP_TABLE.rearrange(chunk0Low)).toLong();
                long op1 = curlified1.eq(OP_TABLE.rearrange(chunk1Low)).toLong();
                long op = op0 | (op1 << HALF_BLOCK_BITS);

                tapeLength = writeDelayedMask(tape, tapeLength, blockIndex, prevStructurals);
                blockIndex += BLOCK_SIZE;

                long scalar = ~(op | whitespace);
                if (quote == 0) {
                    long followsScalar = (scalar << 1) | prevScalar;
                    prevScalar = scalar >>> 63;
                    long potentialScalarStart = scalar & ~followsScalar;
                    if (prevInString == 0) {
                        prevStructurals = op | potentialScalarStart;
                    } else {
                        prevStructurals = 0;
                        long unescaped0 = chunk0.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                        long unescaped1 = chunk1.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                        unescapedCharsError |= (unescaped0 | (unescaped1 << HALF_BLOCK_BITS));
                    }
                    continue;
                }

                long nonQuoteScalar = scalar & ~quote;
                long followsNonQuoteScalar = (nonQuoteScalar << 1) | prevScalar;
                prevScalar = nonQuoteScalar >>> 63;
                long potentialScalarStart = scalar & ~followsNonQuoteScalar;
                long potentialStructuralStart = op | potentialScalarStart;
                long inString = inStringMask(quote, prevInString);
                prevInString = inString >> 63;
                prevStructurals = (potentialStructuralStart | quote) & ~(inString ^ quote);
                if (inString != 0) {
                    long unescaped0 = chunk0.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                    long unescaped1 = chunk1.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                    long unescaped = unescaped0 | (unescaped1 << HALF_BLOCK_BITS);
                    unescapedCharsError |= unescaped & inString;
                }
            }

            int remaining = input.length - offset;
            VectorMask<Byte> mask0 = SPECIES_256.indexInRange(0, Math.min(remaining, HALF_BLOCK_BITS));
            VectorMask<Byte> mask1 = remaining <= HALF_BLOCK_BITS
                    ? VectorMask.fromLong(SPECIES_256, 0L)
                    : SPECIES_256.indexInRange(0, remaining - HALF_BLOCK_BITS);
            long validMask = blockValidMask(remaining);
            ByteVector chunk0 = ByteVector.fromArray(SPECIES_256, input, offset, mask0);
            ByteVector chunk1 = ByteVector.fromArray(SPECIES_256, input, offset + HALF_BLOCK_BITS, mask1);

            long backslash0 = chunk0.eq(BACKSLASH).toLong();
            long backslash1 = chunk1.eq(BACKSLASH).toLong();
            long backslash = backslash0 | (backslash1 << HALF_BLOCK_BITS);

            long rawQuote0 = chunk0.eq(QUOTE).toLong();
            long rawQuote1 = chunk1.eq(QUOTE).toLong();
            long rawQuote = rawQuote0 | (rawQuote1 << HALF_BLOCK_BITS);

            long quote;
            if (rawQuote == 0) {
                quote = 0;
            } else {
                long escaped;
                if (backslash == 0) {
                    escaped = prevEscaped;
                } else {
                    backslash &= ~prevEscaped;
                    long followsEscape = (backslash << 1) | prevEscaped;
                    long oddSequenceStarts = backslash & ODD_BITS_MASK & ~followsEscape;
                    long sequencesStartingOnEvenBits = oddSequenceStarts + backslash;
                    long invertMask = sequencesStartingOnEvenBits << 1;
                    escaped = (EVEN_BITS_MASK ^ invertMask) & followsEscape;
                }
                quote = rawQuote & ~escaped;
            }

            VectorShuffle<Byte> chunk0Low = chunk0.and(LOW_NIBBLE_MASK).toShuffle();
            VectorShuffle<Byte> chunk1Low = chunk1.and(LOW_NIBBLE_MASK).toShuffle();

            long whitespace0 = chunk0.eq(WHITESPACE_TABLE.rearrange(chunk0Low)).toLong();
            long whitespace1 = chunk1.eq(WHITESPACE_TABLE.rearrange(chunk1Low)).toLong();
            long whitespace = (whitespace0 | (whitespace1 << HALF_BLOCK_BITS)) & validMask;

            ByteVector curlified0 = chunk0.or((byte) 0x20);
            ByteVector curlified1 = chunk1.or((byte) 0x20);
            long op0 = curlified0.eq(OP_TABLE.rearrange(chunk0Low)).toLong();
            long op1 = curlified1.eq(OP_TABLE.rearrange(chunk1Low)).toLong();
            long op = (op0 | (op1 << HALF_BLOCK_BITS)) & validMask;

            tapeLength = writeDelayedMask(tape, tapeLength, blockIndex, prevStructurals);
            blockIndex += BLOCK_SIZE;

            long scalar = validMask & ~(op | whitespace);
            if (quote == 0) {
                long followsScalar = (scalar << 1) | prevScalar;
                long potentialScalarStart = scalar & ~followsScalar;
                if (prevInString == 0) {
                    prevStructurals = op | potentialScalarStart;
                } else {
                    prevStructurals = 0;
                    long unescaped0 = chunk0.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                    long unescaped1 = chunk1.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                    unescapedCharsError |= (unescaped0 | (unescaped1 << HALF_BLOCK_BITS)) & validMask;
                }
            } else {
                long nonQuoteScalar = scalar & ~quote;
                long followsNonQuoteScalar = (nonQuoteScalar << 1) | prevScalar;
                long potentialScalarStart = scalar & ~followsNonQuoteScalar;
                long potentialStructuralStart = op | potentialScalarStart;
                long inString = inStringMask(quote, prevInString);
                prevInString = inString >> 63;
                prevStructurals = (potentialStructuralStart | quote) & ~(inString ^ quote);
                if (inString != 0) {
                    long unescaped0 = chunk0.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                    long unescaped1 = chunk1.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                    long unescaped = (unescaped0 | (unescaped1 << HALF_BLOCK_BITS)) & validMask;
                    unescapedCharsError |= unescaped & inString;
                }
            }

            if (prevInString != 0) {
                throw new JsonException("Unclosed string. A string is opened, but never closed.");
            }
            if (unescapedCharsError != 0) {
                throw new JsonException("Unescaped characters. Within strings, there are characters that should be escaped.");
            }
            return writeDelayedMask(tape, tapeLength, blockIndex, prevStructurals);
        }

        @Override
        public String name() {
            return "256-bit";
        }
    }

    private static final class Index512 implements IndexImplementation {
        @Override
        public int createTape(byte[] input, Workspace workspace) {
            int[] tape = workspace.values;
            int tapeLength = 0;
            long prevInString = 0;
            long prevEscaped = 0;
            long prevStructurals = 0;
            long unescapedCharsError = 0;
            long prevScalar = 0;

            int loopBound = SPECIES_512.loopBound(input.length);
            int offset = 0;
            int blockIndex = 0;
            for (; offset < loopBound; offset += BLOCK_SIZE) {
                ByteVector chunk = ByteVector.fromArray(SPECIES_512, input, offset);

                long backslash = chunk.eq(BACKSLASH).toLong();
                long rawQuote = chunk.eq(QUOTE).toLong();

                long quote;
                if (rawQuote == 0) {
                    prevEscaped = backslash == 0 ? 0 : endsWithOddBackslashRun(backslash, BLOCK_SIZE, prevEscaped != 0) ? 1 : 0;
                    quote = 0;
                } else {
                    long escaped;
                    if (backslash == 0) {
                        escaped = prevEscaped;
                        prevEscaped = 0;
                    } else {
                        backslash &= ~prevEscaped;
                        long followsEscape = (backslash << 1) | prevEscaped;
                        long oddSequenceStarts = backslash & ODD_BITS_MASK & ~followsEscape;
                        long sequencesStartingOnEvenBits = oddSequenceStarts + backslash;
                        prevEscaped = ((oddSequenceStarts >>> 1)
                                + (backslash >>> 1)
                                + ((oddSequenceStarts & backslash) & 1)) >>> 63;
                        long invertMask = sequencesStartingOnEvenBits << 1;
                        escaped = (EVEN_BITS_MASK ^ invertMask) & followsEscape;
                    }
                    quote = rawQuote & ~escaped;
                }

                VectorShuffle<Byte> chunkLow = chunk.and(LOW_NIBBLE_MASK).toShuffle();
                long whitespace = chunk.eq(WHITESPACE_TABLE.rearrange(chunkLow)).toLong();
                long op = chunk.or((byte) 0x20).eq(OP_TABLE.rearrange(chunkLow)).toLong();

                tapeLength = writeDelayedMask(tape, tapeLength, blockIndex, prevStructurals);
                blockIndex += BLOCK_SIZE;

                long scalar = ~(op | whitespace);
                if (quote == 0) {
                    long followsScalar = (scalar << 1) | prevScalar;
                    prevScalar = scalar >>> 63;
                    long potentialScalarStart = scalar & ~followsScalar;
                    if (prevInString == 0) {
                        prevStructurals = op | potentialScalarStart;
                    } else {
                        prevStructurals = 0;
                        unescapedCharsError |= chunk.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                    }
                    continue;
                }

                long nonQuoteScalar = scalar & ~quote;
                long followsNonQuoteScalar = (nonQuoteScalar << 1) | prevScalar;
                prevScalar = nonQuoteScalar >>> 63;
                long potentialScalarStart = scalar & ~followsNonQuoteScalar;
                long potentialStructuralStart = op | potentialScalarStart;
                long inString = inStringMask(quote, prevInString);
                prevInString = inString >> 63;
                prevStructurals = (potentialStructuralStart | quote) & ~(inString ^ quote);
                if (inString != 0) {
                    long unescaped = chunk.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong();
                    unescapedCharsError |= unescaped & inString;
                }
            }

            int remaining = input.length - offset;
            VectorMask<Byte> mask = SPECIES_512.indexInRange(0, remaining);
            long validMask = blockValidMask(remaining);
            ByteVector chunk = ByteVector.fromArray(SPECIES_512, input, offset, mask);

            long backslash = chunk.eq(BACKSLASH).toLong();
            long rawQuote = chunk.eq(QUOTE).toLong();

            long quote;
            if (rawQuote == 0) {
                quote = 0;
            } else {
                long escaped;
                if (backslash == 0) {
                    escaped = prevEscaped;
                } else {
                    backslash &= ~prevEscaped;
                    long followsEscape = (backslash << 1) | prevEscaped;
                    long oddSequenceStarts = backslash & ODD_BITS_MASK & ~followsEscape;
                    long sequencesStartingOnEvenBits = oddSequenceStarts + backslash;
                    long invertMask = sequencesStartingOnEvenBits << 1;
                    escaped = (EVEN_BITS_MASK ^ invertMask) & followsEscape;
                }
                quote = rawQuote & ~escaped;
            }

            VectorShuffle<Byte> chunkLow = chunk.and(LOW_NIBBLE_MASK).toShuffle();
            long whitespace = chunk.eq(WHITESPACE_TABLE.rearrange(chunkLow)).toLong() & validMask;
            long op = chunk.or((byte) 0x20).eq(OP_TABLE.rearrange(chunkLow)).toLong() & validMask;

            tapeLength = writeDelayedMask(tape, tapeLength, blockIndex, prevStructurals);
            blockIndex += BLOCK_SIZE;

            long scalar = validMask & ~(op | whitespace);
            if (quote == 0) {
                long followsScalar = (scalar << 1) | prevScalar;
                long potentialScalarStart = scalar & ~followsScalar;
                if (prevInString == 0) {
                    prevStructurals = op | potentialScalarStart;
                } else {
                    prevStructurals = 0;
                    unescapedCharsError |= chunk.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong() & validMask;
                }
            } else {
                long nonQuoteScalar = scalar & ~quote;
                long followsNonQuoteScalar = (nonQuoteScalar << 1) | prevScalar;
                long potentialScalarStart = scalar & ~followsNonQuoteScalar;
                long potentialStructuralStart = op | potentialScalarStart;
                long inString = inStringMask(quote, prevInString);
                prevInString = inString >> 63;
                prevStructurals = (potentialStructuralStart | quote) & ~(inString ^ quote);
                if (inString != 0) {
                    long unescaped = chunk.compare(UNSIGNED_LE_COMPARISON, LAST_CONTROL_CHARACTER).toLong() & validMask;
                    unescapedCharsError |= unescaped & inString;
                }
            }

            if (prevInString != 0) {
                throw new JsonException("Unclosed string. A string is opened, but never closed.");
            }
            if (unescapedCharsError != 0) {
                throw new JsonException("Unescaped characters. Within strings, there are characters that should be escaped.");
            }
            return writeDelayedMask(tape, tapeLength, blockIndex, prevStructurals);
        }

        @Override
        public String name() {
            return "512-bit";
        }
    }

    private static long inStringMask(long quote, long prevInString) {
        if ((quote & (quote - 1)) == 0) {
            return (-quote) ^ prevInString;
        }
        return prefixXor(quote) ^ prevInString;
    }

    private static long blockValidMask(int blockLength) {
        return blockLength == BLOCK_SIZE ? -1L : (1L << blockLength) - 1;
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

    private static boolean endsWithOddBackslashRun(long backslashes, int length, boolean previousBlockEndedOddRun) {
        int trailingBackslashes = countTrailingBackslashes(backslashes, length);
        if (trailingBackslashes == 0) {
            return false;
        }
        if (trailingBackslashes == length) {
            return previousBlockEndedOddRun ^ ((length & 1) != 0);
        }
        return (trailingBackslashes & 1) != 0;
    }

    private static int countTrailingBackslashes(long backslashes, int length) {
        if (length == 0) {
            return 0;
        }
        long valid = backslashes & blockValidMask(length);
        long shifted = valid << (Long.SIZE - length);
        return Long.numberOfLeadingZeros(~shifted);
    }

    private static int writeDelayedMask(int[] tape, int length, int blockIndex, long bits) {
        if (bits == 0) {
            return length;
        }

        int idx = blockIndex - BLOCK_SIZE;
        int cnt = Long.bitCount(bits);
        for (int i = 0; i < 8; i++) {
            tape[length + i] = idx + Long.numberOfTrailingZeros(bits);
            bits &= bits - 1;
        }

        if (cnt > 8) {
            for (int i = 8; i < 16; i++) {
                tape[length + i] = idx + Long.numberOfTrailingZeros(bits);
                bits &= bits - 1;
            }
            if (cnt > 16) {
                int i = 16;
                do {
                    tape[length + i] = idx + Long.numberOfTrailingZeros(bits);
                    bits &= bits - 1;
                    i++;
                } while (i < cnt);
            }
        }
        return length + cnt;
    }

    private static VectorOperators.Comparison unsignedLeComparison() {
        try {
            return (VectorOperators.Comparison) VectorOperators.class.getField("UNSIGNED_LE").get(null);
        } catch (ReflectiveOperationException ignored) {
            try {
                return (VectorOperators.Comparison) VectorOperators.class.getField("ULE").get(null);
            } catch (ReflectiveOperationException e) {
                throw new ExceptionInInitializerError(e);
            }
        }
    }
}
