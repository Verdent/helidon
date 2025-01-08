package io.helidon.json.binding.factories;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonBinding;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonBindingFactory;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
final class ListBindingFactory<T> implements TypedJsonBindingFactory<List<T>> {

    @Override
    public JsonDeserializer<List<T>> createDeserializer(JsonBinding jsonBinding, Type type) {
        return new ListConverter<>(jsonBinding, type);
    }

    @Override
    public JsonSerializer<List<T>> createSerializer(JsonBinding jsonBinding, Type type) {
        return new ListConverter<>(jsonBinding, type);
    }

    @Override
    public Class<?> type() {
        return List.class;
    }

    private static final class ListConverter<T> implements JsonConverter<List<T>> {

        private final JsonDeserializer<T> deserializer;
        private final JsonSerializer<T> serializer;

        private ListConverter(JsonBinding jsonBinding, Type type) {
            if (type instanceof ParameterizedType parameterizedType) {
                deserializer = jsonBinding.getDeserializer(parameterizedType.getActualTypeArguments()[0]);
                serializer = jsonBinding.getSerializer(parameterizedType.getActualTypeArguments()[0]);
            } else {
                deserializer = jsonBinding.getDeserializer(GenericType.OBJECT);
                serializer = jsonBinding.getSerializer(GenericType.OBJECT);
            }
        }

        @Override
        public void toJson(Generator generator, List<T> instance) {
            if (instance == null) {
                generator.writeNull();
                return;
            }
            generator.writeArrayStart();
            boolean first = true;
            for (T value : instance) {
                if (!first) {
                    generator.writeComma();
                }
                serializer.toJson(generator, value);
                if (first) {
                    first = false;
                }
            }
            generator.writeArrayEnd();
        }

        @Override
        public List<T> fromJson(JsonParser parser) {
            if (parser.checkNull()) {
                return null;
            }
            List<T> list = new ArrayList<>();
            byte lastByte = parser.lastByte();
            if (lastByte != '[') {
                throw new JsonException("Array start expected. Found: " + Character.toString(lastByte));
            }
            lastByte = parser.nextToken();
            if (lastByte != ']') {
                list.add(deserializer.fromJson(parser));
                lastByte = parser.nextToken();
                while (lastByte == ',') {
                    parser.nextToken();
                    list.add(deserializer.fromJson(parser));
                    lastByte = parser.nextToken();
                }
                if (lastByte != ']') {
                    throw new JsonException("Array end expected, received: " + Character.toString(lastByte));
                }
            }
            return list;
        }

    }

}
