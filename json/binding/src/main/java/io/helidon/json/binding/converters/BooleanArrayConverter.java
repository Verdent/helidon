package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.Deserializers;
import io.helidon.json.binding.JsonBindingConfigurator;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.PerLookup
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class BooleanArrayConverter implements JsonConverter<boolean[]> {

    private static final GenericType<boolean[]> TYPE = GenericType.create(boolean[].class);

    private final boolean[] emptyArray = new boolean[0];
    private JsonDeserializer<Boolean> deserializer;
    private JsonSerializer<Boolean> serializer;

    @Override
    public void serialize(Generator generator, boolean[] instance, boolean writeNulls) {
        generator.writeArrayStart();
        for (boolean value : instance) {
            serializer.serialize(generator, value, writeNulls);
        }
        generator.writeArrayEnd();
    }

    @Override
    public boolean[] deserialize(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte != '[') {
            throw new JsonException("Array start expected. Found: " + Character.toString(lastByte));
        }
        boolean[] array = new boolean[5];
        lastByte = parser.nextToken();
        int index = 0;
        if (lastByte != ']') {
            array[index++] = Deserializers.deserialize(parser, deserializer);
            lastByte = parser.nextToken();
            while (lastByte == ',') {
                if (index == array.length) {
                    boolean[] tmp = new boolean[array.length * 2];
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
            boolean[] toReturn = new boolean[index];
            System.arraycopy(array, 0, toReturn, 0, toReturn.length);
            return toReturn;
        }
        return emptyArray;
    }

    @Override
    public void configure(JsonBindingConfigurator jsonBindingConfigurator) {
        deserializer = jsonBindingConfigurator.getDeserializer(boolean.class);
        serializer = jsonBindingConfigurator.getSerializer(boolean.class);
    }

    @Override
    public GenericType<boolean[]> type() {
        return TYPE;
    }
}
