package io.helidon.json.binding.factories;

import java.lang.reflect.Array;
import java.lang.reflect.Type;
import java.util.List;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.BindingFactoryConverter;
import io.helidon.json.binding.BindingFactoryDeserializer;
import io.helidon.json.binding.BindingFactorySerializer;
import io.helidon.json.binding.JsonBindingConfigurer;
import io.helidon.json.binding.JsonConfigurable;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonBindingFactory;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class ArrayBindingFactory<T> implements TypedJsonBindingFactory<T[]> {

    @Override
    public BindingFactoryDeserializer<T[]> createDeserializer(Type type) {
        return new ArrayConverter<>(type);
    }

    @Override
    public BindingFactorySerializer<T[]> createSerializer(Type type) {
        return new ArrayConverter<>(type);
    }

    @Override
    public Class<?> type() {
        return Array.class;
    }

    private static class ArrayConverter<T> implements BindingFactoryConverter<T[]> {

        private final Class<?> componentType;
        private JsonDeserializer<T> deserializer;
        private JsonSerializer<T> serializer;
        private T[] emptyArray;

        private ArrayConverter(Type type) {
            Class<?> classType = (Class<?>) type;
            this.componentType = classType.componentType();
        }

        @Override
        public void toJson(Generator generator, T[] instance, boolean writeNulls) {
            if (instance == null) {
                generator.writeNull();
                return;
            }
            generator.writeArrayStart();
            boolean first = true;
            for (T value : instance) {
                if (value == null && !writeNulls) {
                    continue;
                }
                if (!first) {
                    generator.writeComma();
                } else {
                    first = false;
                }
                serializer.toJson(generator, value, writeNulls);
            }
            generator.writeArrayEnd();
        }

        @Override
        public T[] fromJsonValue(JsonParser parser) {
            byte lastByte = parser.lastByte();
            if (lastByte != '[') {
                throw new JsonException("Array start expected. Found: " + Character.toString(lastByte));
            }
            T[] array = createArrayInstance(5);
            lastByte = parser.nextToken();
            int index = 0;
            if (lastByte != ']') {
                array[index++] = deserializer.fromJson(parser);
                lastByte = parser.nextToken();
                while (lastByte == ',') {
                    if (index == array.length) {
                        T[] tmp = createArrayInstance(array.length * 2);
                        System.arraycopy(array, 0, tmp, 0, array.length);
                        array = tmp;
                    }
                    parser.nextToken();
                    array[index++] = deserializer.fromJson(parser);
                    lastByte = parser.nextToken();
                }
                if (lastByte != ']') {
                    throw new JsonException("Array end expected, received: " + Character.toString(lastByte));
                }
            }
            if (index > 0) {
                T[] toReturn = createArrayInstance(index);
                System.arraycopy(array, 0, toReturn, 0, toReturn.length);
                return toReturn;
            } else if (index == array.length) {
                return array;
            }
            return emptyArray;
        }

        @SuppressWarnings("unchecked")
        private T[] createArrayInstance(int size) {
            return (T[]) Array.newInstance(componentType, size);
        }

        @Override
        @SuppressWarnings("unchecked")
        public void configure(JsonBindingConfigurer jsonBindingConfigurer) {
            deserializer = (JsonDeserializer<T>) jsonBindingConfigurer.getDeserializer(componentType);
            serializer = (JsonSerializer<T>) jsonBindingConfigurer.getSerializer(componentType);
            emptyArray = createArrayInstance(0);
        }
    }
}
