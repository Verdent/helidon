package io.helidon.json.binding;

import io.helidon.json.processor.Generator;

public interface JsonSerializer<T> {

    static <T> boolean writeToJson(Generator generator,
                                   JsonSerializer<T> serializer,
                                   T instance,
                                   String key,
                                   boolean isFirst,
                                   boolean writeNulls) {
        if (instance == null) {
            if (writeNulls) {
                if (!isFirst) {
                    generator.writeComma();
                }
                generator.writeKey(key);
                serializer.writeNull(generator);
                return false;
            }
            return isFirst;
        }
        if (!isFirst) {
            generator.writeComma();
        }
        generator.writeKey(key);
        serializer.toJson(generator, instance, writeNulls);
        return false;
    }

    default void writeNull(Generator generator) {
        generator.writeNull();
    }

    void toJson(Generator generator, T instance, boolean writeNulls);

}
