/*
 * Copyright (c) 2025 Oracle and/or its affiliates.
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

package io.helidon.json;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for ArrayJsonParser string handling functionality.
 * Covers basic strings, escaped characters, Unicode, UTF-8 multibyte sequences, and edge cases.
 */
class ArrayJsonParserStringTest {

    // Basic ASCII string tests
    @Test
    public void testBasicAsciiString() {
        ArrayJsonParser parser = new ArrayJsonParser("\"hello world\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("hello world"));
    }

    @Test
    public void testEmptyString() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is(""));
    }

    @Test
    public void testSingleCharacterString() {
        ArrayJsonParser parser = new ArrayJsonParser("\"a\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("a"));
    }

    @Test
    public void testStringWithSpaces() {
        ArrayJsonParser parser = new ArrayJsonParser("\"  hello   world  \"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("  hello   world  "));
    }

    // Escaped character tests
    @Test
    public void testEscapedQuote() {
        ArrayJsonParser parser = new ArrayJsonParser("\"He said \\\"hello\\\"\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("He said \"hello\""));
    }

    @Test
    public void testEscapedBackslash() {
        ArrayJsonParser parser = new ArrayJsonParser("\"path\\\\to\\\\file\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("path\\to\\file"));
    }

    @Test
    public void testEscapedSolidus() {
        ArrayJsonParser parser = new ArrayJsonParser("\"http:\\/\\/example.com\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("http://example.com"));
    }

    @Test
    public void testEscapedBackspace() {
        ArrayJsonParser parser = new ArrayJsonParser("\"line1\\bline2\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("line1\bline2"));
    }

    @Test
    public void testEscapedFormFeed() {
        ArrayJsonParser parser = new ArrayJsonParser("\"page1\\fpage2\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("page1\fpage2"));
    }

    @Test
    public void testEscapedNewline() {
        ArrayJsonParser parser = new ArrayJsonParser("\"line1\\nline2\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("line1\nline2"));
    }

    @Test
    public void testEscapedCarriageReturn() {
        ArrayJsonParser parser = new ArrayJsonParser("\"line1\\rline2\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("line1\rline2"));
    }

    @Test
    public void testEscapedTab() {
        ArrayJsonParser parser = new ArrayJsonParser("\"col1\\tcol2\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("col1\tcol2"));
    }

    @Test
    public void testMultipleEscapedCharacters() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\n\\t\\r\\f\\b\\\\\\\"\\\"\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("\n\t\r\f\b\\\"\""));
    }

    // Unicode escape sequence tests (\\uXXXX)
    @Test
    public void testUnicodeEscapeBasic() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\u0041\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("A"));
    }

    @Test
    public void testUnicodeEscapeLowercase() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\u0061\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("a"));
    }

    @Test
    public void testUnicodeEscapeEuroSymbol() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\u20AC\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("€"));
    }

    @Test
    public void testUnicodeEscapeMultiple() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\u0048\\u0065\\u006C\\u006C\\u006F\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("Hello"));
    }

    // UTF-8 multibyte sequence tests
    @Test
    public void testUtf8TwoByteSequence() {
        // U+00A9 (copyright symbol) - 2 bytes in UTF-8: C2 A9
        ArrayJsonParser parser = new ArrayJsonParser("\"©\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("©"));
    }

    @Test
    public void testUtf8ThreeByteSequence() {
        // U+20AC (euro symbol) - 3 bytes in UTF-8: E2 82 AC
        ArrayJsonParser parser = new ArrayJsonParser("\"€\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("€"));
    }

    @Test
    public void testUtf8FourByteSequence() {
        // U+1F600 (grinning face emoji) - 4 bytes in UTF-8: F0 9F 98 80
        ArrayJsonParser parser = new ArrayJsonParser("\"😀\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("😀"));
    }

    // Surrogate pair tests
    @Test
    public void testSurrogatePairInJson() {
        // U+1F600 (grinning face) as surrogate pair in JSON: \uD83D\uDE00
        ArrayJsonParser parser = new ArrayJsonParser("\"\\uD83D\\uDE00\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("😀"));
    }

    @Test
    public void testMultipleSurrogatePairs() {
        // Multiple emojis with surrogate pairs
        ArrayJsonParser parser = new ArrayJsonParser("\"\\uD83D\\uDE00\\uD83D\\uDE01\\uD83D\\uDE02\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("😀😁😂"));
    }

    @Test
    public void testMixedAsciiAndSurrogates() {
        ArrayJsonParser parser = new ArrayJsonParser("\"Hello \\uD83D\\uDE00 World\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("Hello 😀 World"));
    }

    // Error case tests
    @Test
    public void testInvalidUnicodeEscape() {
        // Invalid hex digit 'G'
        ArrayJsonParser parser = new ArrayJsonParser("\"\\u004G\"".getBytes(StandardCharsets.UTF_8));
        assertThrows(JsonException.class, parser::readString);
    }

    @Test
    public void testIncompleteUnicodeEscape() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\u004\"".getBytes(StandardCharsets.UTF_8));
        assertThrows(JsonException.class, parser::readString);
    }

    @Test
    public void testInvalidUtf8Sequence() {
        // Invalid UTF-8: isolated continuation byte
        byte[] invalidUtf8 = new byte[]{'"', (byte) 0x80, '"'};
        ArrayJsonParser parser = new ArrayJsonParser(invalidUtf8);
        assertThrows(JsonException.class, parser::readString);
    }

    @Test
    public void testIncompleteUtf8Sequence() {
        // Incomplete 3-byte sequence: E2 82 (missing AC)
        byte[] incompleteUtf8 = new byte[]{'"', (byte) 0xE2, (byte) 0x82, '"'};
        ArrayJsonParser parser = new ArrayJsonParser(incompleteUtf8);
        assertThrows(JsonException.class, parser::readString);
    }

    @Test
    public void testUnterminatedString() {
        ArrayJsonParser parser = new ArrayJsonParser("\"hello".getBytes(StandardCharsets.UTF_8));
        assertThrows(JsonException.class, parser::readString);
    }

    @Test
    public void testInvalidEscapeSequence() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\z\"".getBytes(StandardCharsets.UTF_8));
        assertThrows(JsonException.class, parser::readString);
    }

    @Test
    public void testHighSurrogateWithoutLowSurrogate() {
        // High surrogate followed by regular character instead of low surrogate
        ArrayJsonParser parser = new ArrayJsonParser("\"\\uD83DA\"".getBytes(StandardCharsets.UTF_8));
        assertThrows(JsonException.class, parser::readString);
    }

    @Test
    public void testLowSurrogateWithoutHighSurrogate() {
        // Low surrogate without preceding high surrogate
        ArrayJsonParser parser = new ArrayJsonParser("\"\\uDE00\"".getBytes(StandardCharsets.UTF_8));
        assertThrows(JsonException.class, parser::readString);
    }

    // Edge case tests
    @Test
    public void testStringWithNullCharacter() {
        ArrayJsonParser parser = new ArrayJsonParser("\"hello\\u0000world\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("hello\u0000world"));
    }

    @Test
    public void testStringWithControlCharacters() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\u0001\\u0002\\u001F\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("\u0001\u0002\u001F"));
    }

    @Test
    public void testVeryLongString() {
        int count = 10000;
        String expected = "a".repeat(count);
        String longString = "\"" + expected + "\"";

        ArrayJsonParser parser = new ArrayJsonParser(longString.getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result.length(), is(count));
        assertThat(result, is(expected));
    }

    @Test
    public void testStringWithEscapedQuotesAtBoundaries() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\\"hello\\\"world\\\"\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("\"hello\"world\""));
    }

    @Test
    public void testComplexMixedString() {
        // Mix of ASCII, escaped chars, Unicode escapes, and UTF-8 multibyte chars
        ArrayJsonParser parser = new ArrayJsonParser("\"Hello\\n\\u0041\\u4E2D\\u6587©\\uD83D\\uDE00\"".getBytes(StandardCharsets.UTF_8));
        String result = parser.readString();
        assertThat(result, is("Hello\nA中文©😀"));
    }

    // Test readChar method specifically (uses decodeUtf8ToChar)
    @Test
    public void testReadCharAscii() {
        ArrayJsonParser parser = new ArrayJsonParser("\"A\"".getBytes(StandardCharsets.UTF_8));
        char result = parser.readChar();
        assertEquals('A', result);
    }

    @Test
    public void testReadCharUnicodeEscape() {
        ArrayJsonParser parser = new ArrayJsonParser("\"\\u0042\"".getBytes(StandardCharsets.UTF_8));
        char result = parser.readChar();
        assertEquals('B', result);
    }

    @Test
    public void testReadCharUtf8TwoByte() {
        ArrayJsonParser parser = new ArrayJsonParser("\"©\"".getBytes(StandardCharsets.UTF_8));
        char result = parser.readChar();
        assertEquals('©', result);
    }

    @Test
    public void testReadCharUtf8ThreeByte() {
        ArrayJsonParser parser = new ArrayJsonParser("\"€\"".getBytes(StandardCharsets.UTF_8));
        char result = parser.readChar();
        assertEquals('€', result);
    }

    @Test
    public void testReadCharRejectsSurrogate() {
        // This should fail because surrogate pairs require 2 chars
        ArrayJsonParser parser = new ArrayJsonParser("\"\\uD83D\\uDE00\"".getBytes(StandardCharsets.UTF_8));
        assertThrows(JsonException.class, parser::readChar);
    }
}
