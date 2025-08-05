package io.helidon.json.binding.factories;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.BindingFactoryConverter;
import io.helidon.json.binding.BindingFactoryDeserializer;
import io.helidon.json.binding.BindingFactorySerializer;
import io.helidon.json.binding.JsonBindingConfigurer;
import io.helidon.json.binding.JsonContext;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonBindingFactory;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class ListBindingFactory implements TypedJsonBindingFactory<List<?>> {

    @Override
    public BindingFactoryDeserializer<List<?>> createDeserializer(Type type) {
        return new ListConverter(type);
    }

    @Override
    public BindingFactorySerializer<List<?>> createSerializer(Type type) {
        return new ListConverter(type);
    }

    @Override
    public Class<?> type() {
        return List.class;
    }

    private static final class ListConverter implements BindingFactoryConverter<List<?>> {

        private final Type componentType;
        private JsonDeserializer<Object> deserializer;
        private JsonSerializer<Object> serializer;

        public ListConverter(Type type) {
            if (type instanceof ParameterizedType parameterizedType) {
                componentType = parameterizedType.getActualTypeArguments()[0];
            } else {
                componentType = GenericType.OBJECT;
            }
        }

        @Override
        public void toJson(Generator generator, List<?> instance, boolean writeNulls) {
            if (instance == null) {
                generator.writeNull();
                return;
            }
            generator.writeArrayStart();
            boolean first = true;
            for (Object value : instance) {
                if (value == null && !writeNulls) {
                    continue;
                }
                if (!first) {
                    generator.writeComma();
                }
                serializer.toJson(generator, value, writeNulls);
                if (first) {
                    first = false;
                }
            }
            generator.writeArrayEnd();
        }

        @Override
        public List<?> fromJsonValue(JsonParser parser) {
            List<Object> list = new ArrayList<>();
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

        @Override
        public void configure(JsonBindingConfigurer jsonBindingConfigurer, JsonContext jsonContext) {
            deserializer = jsonBindingConfigurer.getDeserializer(componentType);
            serializer = jsonBindingConfigurer.getSerializer(componentType);
        }
    }
}
