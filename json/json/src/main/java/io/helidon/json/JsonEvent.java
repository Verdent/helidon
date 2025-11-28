package io.helidon.json;

public enum JsonEvent {

    OBJECT_START,
    OBJECT_END,
    ARRAY_START,
    ARRAY_END,
    VALUE_NULL,
    VALUE_STRING,
    VALUE_NUMBER,
    VALUE_BOOLEAN,
    KEY

}
