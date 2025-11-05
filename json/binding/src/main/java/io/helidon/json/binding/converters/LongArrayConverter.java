package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.Deserializers;
import io.helidon.json.binding.JsonBindingConfigurator;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.PerLookup
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class LongArrayConverter implements TypedJsonConverter<long[]> {

    private static final GenericType<long[]> TYPE = GenericType.create(long[].class);

    private final long[] emptyArray = new long[0];
    private JsonDeserializer<Long> deserializer;
    private JsonSerializer<Long> serializer;

    @Override
    public void serialize(Generator generator, long[] instance, boolean writeNulls) {
        generator.writeArrayStart();
        boolean first = true;
        for (long value : instance) {
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
    public long[] deserialize(JsonParser parser) {
        byte lastByte = parser.lastByte();
        if (lastByte != '[') {
            throw new JsonException("Array start expected. Found: " + Character.toString(lastByte));
        }
        long[] array = new long[5];
        lastByte = parser.nextToken();
        int index = 0;
        if (lastByte != ']') {
            array[index++] = Deserializers.deserialize(parser, deserializer);
            lastByte = parser.nextToken();
            while (lastByte == ',') {
                if (index == array.length) {
                    long[] tmp = new long[array.length * 2];
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
            long[] toReturn = new long[index];
            System.arraycopy(array, 0, toReturn, 0, toReturn.length);
            return toReturn;
        }
        return emptyArray;
    }

    @Override
    public void configure(JsonBindingConfigurator jsonBindingConfigurator) {
        deserializer = jsonBindingConfigurator.getDeserializer(long.class);
        serializer = jsonBindingConfigurator.getSerializer(long.class);
    }

    @Override
    public GenericType<long[]> type() {
        return TYPE;
    }
}
