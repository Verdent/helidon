package io.helidon.json.binding.factories;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Set;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.BindingFactoryConverter;
import io.helidon.json.binding.BindingFactoryDeserializer;
import io.helidon.json.binding.BindingFactorySerializer;
import io.helidon.json.binding.JsonBindingConfigurer;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.json.binding.TypedJsonBindingFactory;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
final class SetBindingFactory<T> implements TypedJsonBindingFactory<Set<T>> {

    @Override
    public BindingFactoryDeserializer<Set<T>> createDeserializer() {
        return new SetConverter<>();
    }

    @Override
    public BindingFactorySerializer<Set<T>> createSerializer() {
        return new SetConverter<>();
    }

    @Override
    public Class<?> type() {
        return Set.class;
    }

    private static final class SetConverter<T> implements BindingFactoryConverter<Set<T>> {

        private JsonDeserializer<T> deserializer;
        private JsonSerializer<T> serializer;

        @Override
        public void toJson(Generator generator, Set<T> instance) {
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
        public Set<T> fromJsonValue(JsonParser parser) {
            Set<T> set = new HashSet<>();
            byte lastByte = parser.lastByte();
            if (lastByte != '[') {
                throw new JsonException("Array start expected. Found: " + Character.toString(lastByte));
            }
            lastByte = parser.nextToken();
            if (lastByte != ']') {
                set.add(deserializer.fromJson(parser));
                lastByte = parser.nextToken();
                while (lastByte == ',') {
                    parser.nextToken();
                    set.add(deserializer.fromJson(parser));
                    lastByte = parser.nextToken();
                }
                if (lastByte != ']') {
                    throw new JsonException("Array end expected, received: " + Character.toString(lastByte));
                }
            }
            return set;
        }

        @Override
        public void configure(JsonBindingConfigurer jsonBindingConfigurer, Type type) {
            if (type instanceof ParameterizedType parameterizedType) {
                deserializer = jsonBindingConfigurer.getDeserializer(parameterizedType.getActualTypeArguments()[0]);
                serializer = jsonBindingConfigurer.getSerializer(parameterizedType.getActualTypeArguments()[0]);
            } else {
                deserializer = jsonBindingConfigurer.getDeserializer(GenericType.OBJECT);
                serializer = jsonBindingConfigurer.getSerializer(GenericType.OBJECT);
            }
        }
    }

}
