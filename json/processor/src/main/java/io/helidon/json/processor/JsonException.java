package io.helidon.json.processor;

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
