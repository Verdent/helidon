package io.helidon.json.codegen;

import io.helidon.builder.api.Prototype;

class JsonPropertyCustomMethods {

    private JsonPropertyCustomMethods() {
    }

    @Prototype.BuilderMethod
    static <T> void deserializationNameIfNotSet(JsonProperty.BuilderBase<?, ?> builder, String deserializationName) {
        if (builder.deserializationName().isEmpty()) {
            builder.deserializationName(deserializationName);
        }
    }

    @Prototype.BuilderMethod
    static <T> void serializationNameIfNotSet(JsonProperty.BuilderBase<?, ?> builder, String serializationName) {
        if (builder.serializationName().isEmpty()) {
            builder.serializationName(serializationName);
        }
    }
}
