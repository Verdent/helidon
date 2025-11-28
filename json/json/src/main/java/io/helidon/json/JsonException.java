package io.helidon.json;

/**
 * TODO javadoc
 */
public class JsonException extends RuntimeException {

    public JsonException(String message) {
        super(message);
    }

    public JsonException(String message, Exception cause) {
        super(message, cause);
    }

}
