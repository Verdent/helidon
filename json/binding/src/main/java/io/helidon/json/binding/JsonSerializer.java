package io.helidon.json.binding;

import io.helidon.json.processor.Generator;

public interface JsonSerializer<T> {

//    default boolean writeToJson(Generator generator,
//                                JsonSerializer<T> serializer,
//                                T instance,
//                                String key,
//                                boolean previous,
//                                boolean writeEmpty) {
//        if (instance == null) {
//            if (writeEmpty) {
//                if (previous) {
//                    generator.writeComma();
//                }
//                generator.writeKey(key);
//                serializer.writeNull(generator);
//                return true;
//            }
//            return previous;
//        }
//        if (previous) {
//            generator.writeComma();
//        }
//        generator.writeKey(key);
//        serializer.toJson(generator, instance, writeEmpty);
//        return true;
//    }
//
//    default void writeNull(Generator generator) {
//        generator.writeNull();
//    }

    void toJson(Generator generator, T instance);

}
