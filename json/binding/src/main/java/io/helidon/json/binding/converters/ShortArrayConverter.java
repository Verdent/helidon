package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.Deserializers;
import io.helidon.json.binding.JsonBindingConfigurator;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonException;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.PerLookup
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class ShortArrayConverter implements JsonConverter<short[]> {

    private static final GenericType<short[]> TYPE = GenericType.create(short[].class);

    private final short[] emptyArray = new short[0];
    private JsonDeserializer<Short> deserializer;
    private JsonSerializer<Short> serializer;

    @Override
    public void serialize(Generator generator, short[] instance, boolean writeNulls) {
        generator.writeArrayStart();
        for (short value : instance) {
            serializer.serialize(generator, value, writeNulls);
        }
        generator.writeArrayEnd();
    }

    @Override
    public short[] deserialize(JsonParser parser) {
        byte lastByte = parser.currentByte();
        if (lastByte != '[') {
            throw new JsonException("Array start expected. Found: " + Character.toString(lastByte));
        }
        short[] array = new short[5];
        lastByte = parser.nextToken();
        int index = 0;
        if (lastByte == ']') {
            return emptyArray;
        }
        array[index++] = Deserializers.deserialize(parser, deserializer);
        lastByte = parser.nextToken();
        while (lastByte == ',') {
            if (index == array.length) {
                short[] tmp = new short[array.length * 2];
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
        if (index == array.length) {
            return array;
        }
        short[] toReturn = new short[index];
        System.arraycopy(array, 0, toReturn, 0, toReturn.length);
        return toReturn;
    }

    @Override
    public void configure(JsonBindingConfigurator jsonBindingConfigurator) {
        deserializer = jsonBindingConfigurator.getDeserializer(short.class);
        serializer = jsonBindingConfigurator.getSerializer(short.class);
    }

    @Override
    public GenericType<short[]> type() {
        return TYPE;
    }
}
