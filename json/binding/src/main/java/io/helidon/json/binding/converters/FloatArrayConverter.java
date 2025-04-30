package io.helidon.json.binding.converters;

import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonBindingConfigurer;
import io.helidon.json.binding.JsonConfigurable;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

//@Service.Singleton
//@Weight(Weighted.DEFAULT_WEIGHT - 10)
class FloatArrayConverter implements TypedJsonConverter<float[]>, JsonConfigurable {

    private final float[] emptyArray = new float[0];
    private JsonDeserializer<Float> deserializer;
    private JsonSerializer<Float> serializer;

    @Override
    public void toJson(Generator generator, float[] instance, boolean writeNulls) {
        generator.writeArrayStart();
        boolean first = true;
        for (float value : instance) {
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
    public float[] fromJsonValue(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte != '[') {
            throw new JsonException("Array start expected. Found: " + Character.toString(lastByte));
        }
        float[] array = new float[5];
        lastByte = parser.nextToken();
        int index = 0;
        if (lastByte != ']') {
            array[index++] = deserializer.fromJson(parser);
            lastByte = parser.nextToken();
            while (lastByte == ',') {
                if (index == array.length) {
                    float[] tmp = new float[array.length * 2];
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
        if (index == array.length) {
            return array;
        } else if (index > 0) {
            float[] toReturn = new float[index];
            System.arraycopy(array, 0, toReturn, 0, toReturn.length);
            return toReturn;
        }
        return emptyArray;
    }

    @Override
    public void configure(JsonBindingConfigurer jsonBindingConfigurer) {
        deserializer = jsonBindingConfigurer.getDeserializer(float.class);
        serializer = jsonBindingConfigurer.getSerializer(float.class);
    }
}
