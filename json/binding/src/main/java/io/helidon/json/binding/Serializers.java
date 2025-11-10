package io.helidon.json.binding;

import io.helidon.json.processor.Generator;

public final class Serializers {

    private Serializers() {
    }

    public static <T> void serialize(Generator generator,
                                     JsonSerializer<T> serializer,
                                     T instance,
                                     String key,
                                     boolean writeNulls) {
        if (instance == null) {
            if (writeNulls) {
                generator.writeKey(key);
                serializer.serializeNull(generator);
            }
        } else {
            generator.writeKey(key);
            serializer.serialize(generator, instance, writeNulls);
        }
    }

}
