package io.helidon.json.simd;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

class MainTest {

    @Test
    void detectsRootScalarAtStartOfBuffer() {
        byte[] input = "123".getBytes(StandardCharsets.UTF_8);

        Main.Stage1Result result = Main.stage1(input, 0, input.length, Main.INITIAL_STATE);

        assertThat(result.structurals(), is(1L));
        assertThat(result.scalarStarts(), is(1L));
        assertThat(result, is(referenceStage1(input, Main.INITIAL_STATE)));
    }

    @Test
    void honorsCarryAcrossChunkBoundaryForEscapedQuotes() {
        byte[] input = "\"x\"".getBytes(StandardCharsets.UTF_8);
        Main.Stage1State state = new Main.Stage1State(true, true, false);

        Main.Stage1Result result = Main.stage1(input, 0, input.length, state);

        assertThat(result.escaped(), is(1L));
        assertThat(result, is(referenceStage1(input, state)));
    }

    @Test
    void matchesScalarReferenceForRandomizedInputs() {
        byte[] alphabet = new byte[] {
                ' ', '\t', '\n', '\r',
                '{', '}', '[', ']', ':', ',',
                '"', '\\',
                't', 'f', 'n', '1', 'a'
        };
        Random random = new Random(0x5EED5EEDL);

        for (int iteration = 0; iteration < 1_000; iteration++) {
            int length = 1 + random.nextInt(Main.CHUNK_SIZE);
            byte[] input = new byte[length];
            for (int i = 0; i < length; i++) {
                input[i] = alphabet[random.nextInt(alphabet.length)];
            }

            Main.Stage1State state = new Main.Stage1State(
                    random.nextBoolean(),
                    random.nextBoolean(),
                    random.nextBoolean()
            );

            Main.Stage1Result expected = referenceStage1(input, state);
            Main.Stage1Result actual = Main.stage1(input, 0, input.length, state);
            assertThat("mismatch in iteration " + iteration, actual, is(expected));
        }
    }

    @Test
    void scansWholeInputAcrossMultipleChunks() {
        String json = "{\"message\":\""
                + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                + "\\\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                + "\",\"tail\":true,\"value\":123}";
        byte[] input = json.getBytes(StandardCharsets.UTF_8);

        Main.StructuralTape actual = Main.stage1(input);
        Stage1ScanExpectation expected = referenceScan(input, Main.INITIAL_STATE);

        assertThat(actual.tape(), is(expected.structuralIndexes()));
        assertThat(actual.nextState(), is(expected.nextState()));
    }

    @Test
    void matchesScalarReferenceForRandomizedWholeInputs() {
        byte[] alphabet = new byte[] {
                ' ', '\t', '\n', '\r',
                '{', '}', '[', ']', ':', ',',
                '"', '\\',
                't', 'f', 'n', '1', 'a'
        };
        Random random = new Random(0x13579BDFL);

        for (int iteration = 0; iteration < 300; iteration++) {
            int length = 1 + random.nextInt(Main.CHUNK_SIZE * 3);
            byte[] input = new byte[length];
            for (int i = 0; i < length; i++) {
                input[i] = alphabet[random.nextInt(alphabet.length)];
            }

            Main.Stage1State state = new Main.Stage1State(
                    random.nextBoolean(),
                    random.nextBoolean(),
                    random.nextBoolean()
            );

            Main.StructuralTape actual = Main.stage1(input, state);
            Stage1ScanExpectation expected = referenceScan(input, state);

            assertThat("index mismatch in iteration " + iteration, actual.tape(), is(expected.structuralIndexes()));
            assertThat("state mismatch in iteration " + iteration, actual.nextState(), is(expected.nextState()));
        }
    }

    private static Main.Stage1Result referenceStage1(byte[] input, Main.Stage1State initialState) {
        long whitespaces = 0;
        long structuralsOutsideStrings = 0;
        long openingQuotes = 0;
        long scalarStarts = 0;
        long unescapedQuotes = 0;
        long escaped = 0;
        long stringRanges = 0;

        boolean inString = initialState.prevInString();
        boolean pseudoPredecessor = initialState.prevPseudoStructuralPredecessor();
        int backslashRunLength = initialState.prevOddBackslashRun() ? 1 : 0;

        for (int i = 0; i < input.length; i++) {
            byte current = input[i];

            boolean escapedByte = false;
            if (current == '\\') {
                backslashRunLength++;
            } else {
                escapedByte = (backslashRunLength & 1) != 0;
                if (escapedByte) {
                    escaped |= bit(i);
                }
                backslashRunLength = 0;
            }

            boolean quote = current == '"' && !escapedByte;
            if (quote) {
                unescapedQuotes |= bit(i);
                inString = !inString;
            }

            if (inString) {
                stringRanges |= bit(i);
            }

            boolean whitespace = isWhitespace(current);
            boolean structural = isStructural(current) && !inString;
            boolean openingQuote = quote && inString;
            boolean endingQuote = quote && !inString;
            boolean scalarStart = pseudoPredecessor && !whitespace && !structural && !quote && !inString;

            if (whitespace) {
                whitespaces |= bit(i);
            }
            if (structural) {
                structuralsOutsideStrings |= bit(i);
            }
            if (openingQuote) {
                openingQuotes |= bit(i);
            }
            if (scalarStart) {
                scalarStarts |= bit(i);
            }

            pseudoPredecessor = whitespace || structural || endingQuote;
        }

        Main.Stage1State nextState = new Main.Stage1State(
                inString,
                (backslashRunLength & 1) != 0,
                pseudoPredecessor
        );

        long structurals = structuralsOutsideStrings | openingQuotes | scalarStarts;
        return new Main.Stage1Result(
                structurals,
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

    private static Stage1ScanExpectation referenceScan(byte[] input, Main.Stage1State initialState) {
        List<Integer> indexes = new ArrayList<>();
        Main.Stage1State state = initialState;

        int chunkCount = (input.length + Main.CHUNK_SIZE - 1) / Main.CHUNK_SIZE;
        for (int chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
            int offset = chunkIndex * Main.CHUNK_SIZE;
            int length = Math.min(Main.CHUNK_SIZE, input.length - offset);
            byte[] chunk = new byte[length];
            System.arraycopy(input, offset, chunk, 0, length);

            Main.Stage1Result result = referenceStage1(chunk, state);
            appendIndexes(indexes, result.structurals(), offset);
            state = result.nextState();
        }

        int[] structuralIndexes = new int[indexes.size()];
        for (int i = 0; i < indexes.size(); i++) {
            structuralIndexes[i] = indexes.get(i);
        }
        return new Stage1ScanExpectation(structuralIndexes, state);
    }

    private static boolean isWhitespace(byte value) {
        return value == ' ' || value == '\t' || value == '\n' || value == '\r';
    }

    private static boolean isStructural(byte value) {
        return value == '{' || value == '}' || value == '[' || value == ']' || value == ':' || value == ',';
    }

    private static long bit(int index) {
        return 1L << index;
    }

    private static void appendIndexes(List<Integer> indexes, long mask, int baseOffset) {
        long remaining = mask;
        while (remaining != 0) {
            int bitIndex = Long.numberOfTrailingZeros(remaining);
            indexes.add(baseOffset + bitIndex);
            remaining &= remaining - 1;
        }
    }

    private record Stage1ScanExpectation(int[] structuralIndexes, Main.Stage1State nextState) {
    }
}
