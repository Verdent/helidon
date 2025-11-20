package io.helidon.json.processor;

import java.io.InputStream;
import java.util.Objects;

///**
// * A streaming JSON parser interface for parsing JSON data from various sources.
// * <p>
// * This interface provides methods to parse JSON content in a streaming fashion,
// * allowing for efficient processing of large JSON documents without loading
// * the entire content into memory at once. It supports parsing from strings,
// * input streams, and pre-parsed JSON values.
// * </p>
// * <p>
// * The parser operates on a byte-by-byte basis, providing low-level access to
// * JSON tokens and values. Implementations may buffer data internally for
// * performance optimization.
// * </p>
// *
// * @see JsonValue
// * @see JsonObject
// * @see JsonArray
// */
public interface JsonParser {

    /**
     * Creates a new JSON parser from a JSON string.
     * <p>
     * This method creates an in-memory parser that processes the entire JSON string
     * at once. Suitable for parsing small to medium-sized JSON content.
     * </p>
     *
     * @param json the JSON string to parse
     * @return a new JsonParser instance
     */
    static JsonParser create(String json) {
        Objects.requireNonNull(json);
        return new ArrayJsonParser(json);
    }

    /**
     * Creates a new JSON parser from an input stream with default buffer size.
     * <p>
     * This method creates a streaming parser that reads JSON content from the
     * input stream incrementally. Suitable for parsing large JSON content or
     * streaming sources.
     * </p>
     *
     * @param inputStream the input stream containing JSON data
     * @return a new JsonParser instance
     */
    static JsonParser create(InputStream inputStream) {
        Objects.requireNonNull(inputStream);
        return new JsonStreamParser(inputStream);
    }

    /**
     * Creates a new JSON parser from an input stream with specified buffer size.
     * <p>
     * This method creates a streaming parser with a custom buffer size for
     * reading JSON content from the input stream. Use this when you need to
     * control memory usage for large JSON documents.
     * </p>
     *
     * @param inputStream the input stream containing JSON data
     * @param bufferSize the buffer size in bytes for reading from the stream
     * @return a new JsonParser instance
     */
    static JsonParser create(InputStream inputStream, int bufferSize) {
        Objects.requireNonNull(inputStream);
        if (bufferSize <= 0) {
            throw new IllegalArgumentException("Buffer size must be greater than 0.");
        }
        return new JsonStreamParser(inputStream, bufferSize);
    }

    /**
     * Creates a new JSON parser from a pre-parsed JsonValue.
     * <p>
     * This method wraps an existing JsonValue in a parser interface,
     * allowing JsonValue objects to be used wherever a JsonParser is expected.
     * </p>
     *
     * @param value the JsonValue to wrap in a parser
     * @return a new JsonParser instance
     */
    static JsonParser create(JsonValue value) {
        return new JsonValueParser(value);
    }

    /**
     * Creates an empty JSON parser with no content.
     * <p>
     * This parser has no tokens and {@link #hasNext()} will always return false.
     * Useful for testing or as a placeholder.
     * </p>
     *
     * @return an empty JsonParser instance
     */
    static JsonParser empty() {
        return new ArrayJsonParser();
    }

    /**
     * Creates an empty streaming JSON parser.
     * <p>
     * This parser has no content and {@link #hasNext()} will always return false.
     * Useful for testing streaming scenarios or as a placeholder.
     * </p>
     *
     * @return an empty streaming JsonParser instance
     */
    static JsonParser emptyStream() {
        return new JsonStreamParser();
    }

    /**
     * Checks if there are more tokens available in the JSON stream.
     * <p>
     * This method should be called before attempting to read any tokens
     * to avoid exceptions when reaching the end of the JSON content.
     * </p>
     *
     * @return true if more tokens are available, false if end of stream is reached
     */
    boolean hasNext();

    /**
     * Reads the next byte from the JSON stream.
     * <p>
     * This is a low-level method that advances the parser position by one byte.
     * Most users should prefer higher-level methods like {@link #readJsonValue()}.
     * </p>
     *
     * @return the next byte in the stream
     * @throws JsonException if no more bytes are available or an I/O error occurs
     */
    byte readNextByte();

    /**
     * Reads the next JSON token without consuming it.
     * <p>
     * This method advances the parser to the next significant token (skipping
     * whitespace) but does not consume it. The token can then be read using
     * appropriate read methods.
     * </p>
     *
     * @return the byte value of the next token
     * @throws JsonException if no more tokens are available or parsing fails
     */
    byte nextToken();

    /**
     * Returns the last byte that was read from the stream.
     * <p>
     * This method can be used to inspect the current parser position without
     * advancing it. Useful for debugging or conditional parsing logic.
     * </p>
     *
     * @return the last byte read, or 0 if no bytes have been read yet
     */
    byte lastByte();

    /**
     * Reads a complete JSON value from the current position.
     * <p>
     * This method parses and returns the next complete JSON value (object, array,
     * string, number, boolean, or null) from the current parser position.
     * </p>
     *
     * @return the parsed JsonValue
     * @throws JsonException if parsing fails or no value is available
     * @see JsonValue
     */
    JsonValue readJsonValue();

    /**
     * Reads a JSON object from the current position.
     * <p>
     * This method expects the next token to be an object start ('{') and
     * parses the complete object including all nested values.
     * </p>
     *
     * @return the parsed JsonObject
     * @throws JsonException if the next token is not an object or parsing fails
     * @see JsonObject
     */
    JsonObject readJsonObject();

    /**
     * Reads a JSON array from the current position.
     * <p>
     * This method expects the next token to be an array start ('[') and
     * parses the complete array including all nested values.
     * </p>
     *
     * @return the parsed JsonArray
     * @throws JsonException if the next token is not an array or parsing fails
     * @see JsonArray
     */
    JsonArray readJsonArray();

    /**
     * Reads a JSON string value from the current position.
     * <p>
     * This method expects the next token to be a string and returns
     * the parsed string value.
     * </p>
     *
     * @return the parsed JsonString
     * @throws JsonException if the next token is not a string or parsing fails
     * @see JsonString
     */
    JsonString readJsonString();

    /**
     * Reads a JSON number value from the current position.
     * <p>
     * This method expects the next token to be a number and returns
     * the parsed numeric value.
     * </p>
     *
     * @return the parsed JsonNumber
     * @throws JsonException if the next token is not a number or parsing fails
     * @see JsonNumber
     */
    JsonNumber readJsonNumber();

    /**
     * Reads a string value from the current position.
     * <p>
     * This method expects the next token to be a string and returns
     * the string content as a Java String.
     * </p>
     *
     * @return the string value
     * @throws JsonException if the next token is not a string or parsing fails
     */
    String readString();

    /**
     * Reads a string value and returns its hash code.
     * <p>
     * This method is optimized for performance when only string comparison
     * is needed, avoiding string object allocation.
     * </p>
     *
     * @return the hash code of the string value
     * @throws JsonException if the next token is not a string or parsing fails
     */
    int readStringAsHash();

    /**
     * Reads a number value as a character array.
     * <p>
     * This method provides low-level access to numeric values as character
     * arrays, useful for custom number parsing or when memory efficiency
     * is critical.
     * </p>
     *
     * @return the number as a character array
     * @throws JsonException if the next token is not a number or parsing fails
     */
    char[] readNumberAsArray();

    /**
     * Reads a boolean value from the current position.
     * <p>
     * This method expects the next token to be a boolean (true/false) and
     * returns the corresponding Java boolean value.
     * </p>
     *
     * @return the boolean value
     * @throws JsonException if the next token is not a boolean or parsing fails
     */
    boolean readAsBoolean();

    /**
     * Reads a numeric value as a byte.
     * <p>
     * This method expects the next token to be a number and converts it to a byte.
     * Precision may be lost for large numbers.
     * </p>
     *
     * @return the byte value
     * @throws JsonException if the next token is not a number or parsing fails
     * @throws NumberFormatException if the number cannot be converted to byte
     */
    byte readAsByte();

    /**
     * Reads a numeric value as a short.
     * <p>
     * This method expects the next token to be a number and converts it to a short.
     * Precision may be lost for large numbers.
     * </p>
     *
     * @return the short value
     * @throws JsonException if the next token is not a number or parsing fails
     * @throws NumberFormatException if the number cannot be converted to short
     */
    short readAsShort();

    /**
     * Reads a numeric value as an int.
     * <p>
     * This method expects the next token to be a number and converts it to an int.
     * Precision may be lost for large numbers.
     * </p>
     *
     * @return the int value
     * @throws JsonException if the next token is not a number or parsing fails
     * @throws NumberFormatException if the number cannot be converted to int
     */
    int readAsInt();

    /**
     * Reads a numeric value as a long.
     * <p>
     * This method expects the next token to be a number and converts it to a long.
     * Precision may be lost for large numbers.
     * </p>
     *
     * @return the long value
     * @throws JsonException if the next token is not a number or parsing fails
     * @throws NumberFormatException if the number cannot be converted to long
     */
    long readAsLong();

    /**
     * Reads a numeric value as a float.
     * <p>
     * This method expects the next token to be a number and converts it to a float.
     * Precision may be lost for large numbers.
     * </p>
     *
     * @return the float value
     * @throws JsonException if the next token is not a number or parsing fails
     * @throws NumberFormatException if the number cannot be converted to float
     */
    float readAsFloat();

    /**
     * Reads a numeric value as a double.
     * <p>
     * This method expects the next token to be a number and converts it to a double.
     * </p>
     *
     * @return the double value
     * @throws JsonException if the next token is not a number or parsing fails
     * @throws NumberFormatException if the number cannot be converted to double
     */
    double readAsDouble();

    /**
     * Checks if the current position contains a null value without consuming it.
     * <p>
     * This method peeks at the next value to determine if it's null without
     * advancing the parser position. Useful for conditional parsing logic.
     * </p>
     *
     * @return true if the next value is null, false otherwise
     * @throws JsonException if parsing fails
     */
    boolean checkNull();

    /**
     * Skips the current JSON value without parsing it.
     * <p>
     * This method advances the parser past the current value (object, array,
     * string, number, boolean, or null) without constructing Java objects.
     * Useful for skipping unwanted parts of large JSON documents.
     * </p>
     *
     * @throws JsonException if skipping fails or no value is available
     */
    void skip();

    /**
     * Rolls back the last byte read from the stream.
     * <p>
     * This method allows the parser to back up by one byte, effectively
     * "unreading" the last byte. Useful for parser implementations that
     * need to peek ahead.
     * </p>
     *
     * @throws JsonException if rollback is not supported or fails
     */
    void byteRollback();

}
