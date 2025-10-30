package io.helidon.json.binding;

import io.helidon.json.processor.Generator;

public final class Serializers {

    public static <T> boolean serialize(Generator generator,
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
                serializer.serializeNull(generator);
                return false;
            }
            return isFirst;
        }
        if (!isFirst) {
            generator.writeComma();
        }
        generator.writeKey(key);
        serializer.serialize(generator, instance, writeNulls);
        return false;
    }

}
