package io.helidon.json.binding.converters;

import io.helidon.json.binding.Deserializers;
import io.helidon.json.binding.JsonBindingConfigurer;
import io.helidon.json.binding.JsonConfigurable;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;

//@Service.Singleton
//@Weight(Weighted.DEFAULT_WEIGHT - 10)
class CharArrayConverter implements TypedJsonConverter<char[]>, JsonConfigurable {

    private final char[] emptyArray = new char[0];
    private JsonDeserializer<Character> deserializer;
    private JsonSerializer<Character> serializer;

    @Override
    public void serialize(Generator generator, char[] instance, boolean writeNulls) {
        generator.writeArrayStart();
        boolean first = true;
        for (char value : instance) {
            if (!first) {
                generator.writeComma();
            } else {
                first = false;
            }
            serializer.serialize(generator, value, writeNulls);
        }
        generator.writeArrayEnd();
    }

    @Override
    public char[] deserialize(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte != '[') {
            throw new JsonException("Array start expected. Found: " + Character.toString(lastByte));
        }
        char[] array = new char[5];
        lastByte = parser.nextToken();
        int index = 0;
        if (lastByte != ']') {
            array[index++] = Deserializers.deserialize(parser, deserializer);
            lastByte = parser.nextToken();
            while (lastByte == ',') {
                if (index == array.length) {
                    char[] tmp = new char[array.length * 2];
                    System.arraycopy(array, 0, tmp, 0, array.length);
                    array = tmp;
                }
                parser.nextToken();
                array[index++] = Deserializers.deserialize(parser, deserializer);
                lastByte = parser.nextToken();
            }
            if (lastByte != ']') {
                throw new JsonException("Array end expected, received: " + Character.toString(lastByte));
            }
        }
        if (index == array.length) {
            return array;
        } else if (index > 0) {
            char[] toReturn = new char[index];
            System.arraycopy(array, 0, toReturn, 0, toReturn.length);
            return toReturn;
        }
        return emptyArray;
    }

    @Override
    public void configure(JsonBindingConfigurer jsonBindingConfigurer) {
        deserializer = jsonBindingConfigurer.getDeserializer(char.class);
        serializer = jsonBindingConfigurer.getSerializer(char.class);
    }
}
