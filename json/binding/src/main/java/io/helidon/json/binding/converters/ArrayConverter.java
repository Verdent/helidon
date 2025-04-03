package io.helidon.json.binding.converters;

import java.lang.reflect.Array;

import io.helidon.common.GenericType;
import io.helidon.json.binding.JsonBindingConfigurer;
import io.helidon.json.binding.JsonConfigurable;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;

public class ArrayConverter<T> implements TypedJsonConverter<T[]>, JsonConfigurable {

    private JsonDeserializer<T> deserializer;
    private JsonSerializer<T> serializer;
    private T[] emptyArray;

    private final Class<?> type;

    public ArrayConverter(Class<?> type) {
        this.type = type;
    }

    @Override
    public void toJson(Generator generator, T[] instance) {
        if (instance == null) {
            generator.writeNull();
            return;
        }
        generator.writeArrayStart();
        boolean first = true;
        for (T value : instance) {
            if (!first) {
                generator.writeComma();
            } else {
                first = false;
            }
            serializer.toJson(generator, value);
        }
        generator.writeArrayEnd();
    }

    @Override
    public T[] fromJson(JsonParser parser) {
        if (parser.checkNull()) {
            return null;
        }
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
    protected T[] createArrayInstance(int size) {
        return (T[]) Array.newInstance(type.componentType(), size);
    }

    @Override
    public GenericType<T[]> type() {
        throw new UnsupportedOperationException("This should not be called");
    }

    @Override
    @SuppressWarnings("unchecked")
    public void configure(JsonBindingConfigurer jsonBindingConfigurer) {
        Class<?> componentType = type.componentType();
        deserializer = (JsonDeserializer<T>) jsonBindingConfigurer.getDeserializer(componentType);
        serializer = (JsonSerializer<T>) jsonBindingConfigurer.getSerializer(componentType);
        emptyArray = createArrayInstance(0);
    }
}
