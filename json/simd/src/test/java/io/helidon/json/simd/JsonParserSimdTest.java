/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.json.simd;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;

import io.helidon.json.JsonArray;
import io.helidon.json.JsonObject;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class JsonParserSimdTest {

    @Test
    public void testBuildsTapeForRootScalar() {
        JsonParserSimd parser = createParser("123");

        TapeExpectation expected = expectedTape("123".getBytes(StandardCharsets.UTF_8));
        assertTape(parser, expected);
        assertThat(parser.endsInsideString(), is(expected.endsInsideString()));
        assertThat(parser.endsWithOddBackslashRun(), is(expected.endsWithOddBackslashRun()));
        assertThat(parser.endsAfterPseudoStructuralPredecessor(), is(expected.endsAfterPseudoStructuralPredecessor()));
    }

    @Test
    public void testBuildsTapeAcrossMultipleChunks() {
        String json = "{\"message\":\""
                + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                + "\\\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                + "\",\"tail\":true,\"value\":123}";
        JsonParserSimd parser = createParser(json);

        TapeExpectation expected = expectedTape(json.getBytes(StandardCharsets.UTF_8));
        assertTape(parser, expected);
        assertThat(parser.endsInsideString(), is(expected.endsInsideString()));
        assertThat(parser.endsWithOddBackslashRun(), is(expected.endsWithOddBackslashRun()));
        assertThat(parser.endsAfterPseudoStructuralPredecessor(), is(expected.endsAfterPseudoStructuralPredecessor()));
    }

    @Test
    public void testNextTokenNavigatesByTape() {
        JsonParserSimd parser = createParser("{\"key\":true}");

        assertThat(parser.currentByte(), is((byte) '{'));
        assertThat(parser.hasNext(), is(true));
        assertThat(parser.nextToken(), is((byte) '"'));
        assertThat(parser.nextToken(), is((byte) ':'));
        assertThat(parser.nextToken(), is((byte) 't'));
        assertThat(parser.nextToken(), is((byte) '}'));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testReadBooleanTrue() {
        JsonParserSimd parser = createParser("true");

        assertThat(parser.readBoolean(), is(true));
        assertThat(parser.currentByte(), is((byte) 'e'));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testReadBooleanFalse() {
        JsonParserSimd parser = createParser("false");

        assertThat(parser.readBoolean(), is(false));
        assertThat(parser.currentByte(), is((byte) 'e'));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testCheckNull() {
        JsonParserSimd parser = createParser("null");

        assertThat(parser.checkNull(), is(true));
        assertThat(parser.currentByte(), is((byte) 'l'));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testReadJsonString() {
        JsonParserSimd parser = createParser("\"hello\"");

        assertThat(parser.readJsonString().value(), is("hello"));
        assertThat(parser.currentByte(), is((byte) '"'));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testReadString() {
        JsonParserSimd parser = createParser("\"hello\"");

        assertThat(parser.readString(), is("hello"));
        assertThat(parser.currentByte(), is((byte) '"'));
    }

    @Test
    public void testReadStringWithEscapesAndUnicode() {
        JsonParserSimd parser = createParser("\"line\\n\\u0041\"");

        assertThat(parser.readString(), is("line\nA"));
        assertThat(parser.currentByte(), is((byte) '"'));
    }

    @Test
    public void testReadStringAsHash() {
        JsonParserSimd parser = createParser("\"hello\"");

        assertThat(parser.readStringAsHash(), is(fnv1a("hello")));
        assertThat(parser.currentByte(), is((byte) '"'));
    }

    @Test
    public void testReadChar() {
        JsonParserSimd parser = createParser("\"A\"");

        assertThat(parser.readChar(), is('A'));
        assertThat(parser.currentByte(), is((byte) '"'));
    }

    @Test
    public void testReadBinary() {
        byte[] bytes = new byte[] {1, 2, 3, 4, 5};
        String json = "\"" + Base64.getEncoder().encodeToString(bytes) + "\"";
        JsonParserSimd parser = createParser(json);

        assertThat(parser.readBinary(), is(bytes));
        assertThat(parser.currentByte(), is((byte) '"'));
    }

    @Test
    public void testReadJsonNumber() {
        JsonParserSimd parser = createParser("123.5");

        assertThat(parser.readJsonNumber().doubleValue(), is(123.5));
    }

    @Test
    public void testReadJsonValue() {
        JsonParserSimd parser = createParser("{\"name\":\"value\",\"enabled\":true,\"count\":5}");

        JsonObject object = parser.readJsonValue().asObject();
        assertThat(object.stringValue("name").orElseThrow(), is("value"));
        assertThat(object.booleanValue("enabled").orElseThrow(), is(true));
        assertThat(object.intValue("count").orElseThrow(), is(5));
    }

    @Test
    public void testReadJsonObject() {
        JsonParserSimd parser = createParser("{\"key\":\"value\",\"number\":42}");

        JsonObject object = parser.readJsonObject();
        assertThat(object.stringValue("key").orElseThrow(), is("value"));
        assertThat(object.intValue("number").orElseThrow(), is(42));
    }

    @Test
    public void testReadJsonArray() {
        JsonParserSimd parser = createParser("[\"a\",2,true]");

        JsonArray array = parser.readJsonArray();
        assertThat(array.values().size(), is(3));
        assertThat(array.values().get(0).asString().value(), is("a"));
        assertThat(array.values().get(1).asNumber().intValue(), is(2));
        assertThat(array.values().get(2).asBoolean().value(), is(true));
    }

    @Test
    public void testReadInt() {
        JsonParserSimd parser = createParser("12345");

        assertThat(parser.readInt(), is(12345));
        assertThat(parser.currentByte(), is((byte) '5'));
    }

    @Test
    public void testReadLong() {
        JsonParserSimd parser = createParser("1234567890123");

        assertThat(parser.readLong(), is(1234567890123L));
        assertThat(parser.currentByte(), is((byte) '3'));
    }

    @Test
    public void testReadDouble() {
        JsonParserSimd parser = createParser("-123.25e2");

        assertThat(parser.readDouble(), is(-12325.0));
    }

    @Test
    public void testReadBigInteger() {
        JsonParserSimd parser = createParser("123456789012345678901234567890");

        assertThat(parser.readBigInteger().toString(), is("123456789012345678901234567890"));
    }

    @Test
    public void testReadBigDecimal() {
        JsonParserSimd parser = createParser("1234567890.123456789");

        assertThat(parser.readBigDecimal().toPlainString(), is("1234567890.123456789"));
    }

    @Test
    public void testMarkAndReset() {
        JsonParserSimd parser = createParser("{\"key\":null}");

        assertThat(parser.nextToken(), is((byte) '"'));
        parser.mark();
        assertThat(parser.nextToken(), is((byte) ':'));
        assertThat(parser.nextToken(), is((byte) 'n'));
        parser.resetToMark();

        assertThat(parser.currentByte(), is((byte) '"'));
        assertThat(parser.nextToken(), is((byte) ':'));
    }

    @Test
    public void testSkipString() {
        JsonParserSimd parser = createParser("\"hello world\" followed");

        parser.skip();

        assertThat(parser.currentByte(), is((byte) '"'));
        assertThat(parser.hasNext(), is(true));
    }

    @Test
    public void testSkipNumber() {
        JsonParserSimd parser = createParser("123.45e6 followed");

        parser.skip();

        assertThat(parser.currentByte(), is((byte) '6'));
        assertThat(parser.hasNext(), is(true));
    }

    @Test
    public void testSkipNestedObject() {
        JsonParserSimd parser = createParser("{\"outer\":{\"inner\":[1,true,null]}} followed");

        parser.skip();

        assertThat(parser.currentByte(), is((byte) '}'));
        assertThat(parser.hasNext(), is(true));
        assertThat(parser.nextToken(), is((byte) 'f'));
    }

    @Test
    public void testSkipNestedArray() {
        JsonParserSimd parser = createParser("[1,{\"a\":[false]},\"x\"] followed");

        parser.skip();

        assertThat(parser.currentByte(), is((byte) ']'));
        assertThat(parser.hasNext(), is(true));
        assertThat(parser.nextToken(), is((byte) 'f'));
    }

    @Test
    public void testBuildsTapeForRandomizedInput() {
        byte[] alphabet = new byte[] {
                ' ', '\t', '\n', '\r',
                '{', '}', '[', ']', ':', ',',
                '"', '\\',
                't', 'f', 'n', '1', 'a'
        };
        Random random = new Random(0x13579BDFL);

        for (int iteration = 0; iteration < 300; iteration++) {
            int length = 1 + random.nextInt(JsonParserSimd.CHUNK_SIZE * 3);
            byte[] input = new byte[length];
            for (int i = 0; i < length; i++) {
                input[i] = alphabet[random.nextInt(alphabet.length)];
            }

            JsonParserSimd parser = new JsonParserSimd(input);
            TapeExpectation expected = expectedTape(input);

            assertTape(parser, expected);
            assertThat("State mismatch in iteration " + iteration,
                       parser.endsInsideString(),
                       is(expected.endsInsideString()));
            assertThat("Backslash state mismatch in iteration " + iteration,
                       parser.endsWithOddBackslashRun(),
                       is(expected.endsWithOddBackslashRun()));
            assertThat("Predecessor state mismatch in iteration " + iteration,
                       parser.endsAfterPseudoStructuralPredecessor(),
                       is(expected.endsAfterPseudoStructuralPredecessor()));
        }
    }

    @Test
    public void testParserKeepsOriginalBufferSlice() {
        byte[] buffer = "xx{\"key\":1}yy".getBytes(StandardCharsets.UTF_8);
        JsonParserSimd parser = new JsonParserSimd(buffer, 2, 9);

        TapeExpectation expected = expectedTape(buffer, 2, 9);
        assertThat(parser.buffer(), is(buffer));
        assertThat(parser.start(), is(2));
        assertThat(parser.length(), is(9));
        assertTape(parser, expected);
    }

    private static JsonParserSimd createParser(String json) {
        return new JsonParserSimd(json.getBytes(StandardCharsets.UTF_8));
    }

    private static TapeExpectation expectedTape(byte[] input) {
        return expectedTape(input, 0, input.length);
    }

    private static TapeExpectation expectedTape(byte[] input, int start, int length) {
        int[] tape = new int[length];
        int tapeLength = 0;
        boolean inString = false;
        boolean pseudoPredecessor = true;
        int backslashRunLength = 0;

        for (int i = 0; i < length; i++) {
            byte current = input[start + i];

            boolean escapedByte = false;
            if (current == '\\') {
                backslashRunLength++;
            } else {
                escapedByte = (backslashRunLength & 1) != 0;
                backslashRunLength = 0;
            }

            boolean quote = current == '"' && !escapedByte;
            if (quote) {
                inString = !inString;
                if (inString) {
                    tape[tapeLength++] = i;
                }
            } else if (pseudoPredecessor && !isWhitespace(current) && !isStructural(current) && !inString) {
                tape[tapeLength++] = i;
            } else if (isStructural(current) && !inString) {
                tape[tapeLength++] = i;
            }

            boolean endingQuote = quote && !inString;
            pseudoPredecessor = isWhitespace(current) || (isStructural(current) && !inString) || endingQuote;
        }

        return new TapeExpectation(tape, tapeLength, inString, (backslashRunLength & 1) != 0, pseudoPredecessor);
    }

    private static void assertTape(JsonParserSimd parser, TapeExpectation expected) {
        assertThat(parser.tapeLength(), is(expected.tapeLength()));
        for (int i = 0; i < expected.tapeLength(); i++) {
            assertThat(parser.tape()[i], is(expected.tape()[i]));
        }
    }

    private static int fnv1a(String value) {
        int hash = 0x811c9dc5;
        for (int i = 0; i < value.length(); i++) {
            hash ^= value.charAt(i);
            hash *= 0x01000193;
        }
        return hash;
    }

    private static boolean isWhitespace(byte value) {
        return value == ' ' || value == '\t' || value == '\n' || value == '\r';
    }

    private static boolean isStructural(byte value) {
        return value == '{' || value == '}' || value == '[' || value == ']' || value == ':' || value == ',';
    }

    private record TapeExpectation(int[] tape,
                                   int tapeLength,
                                   boolean endsInsideString,
                                   boolean endsWithOddBackslashRun,
                                   boolean endsAfterPseudoStructuralPredecessor) {
    }
}
