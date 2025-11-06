package io.helidon.json.binding.factories;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Set;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.Deserializers;
import io.helidon.json.binding.JsonBindingConfigurator;
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
class SetBindingFactory implements TypedJsonBindingFactory<Set<?>> {

    @Override
    public JsonDeserializer<Set<?>> createDeserializer(Class<? extends Set<?>> type) {
        return new SetConverter(type);
    }

    @Override
    public JsonDeserializer<Set<?>> createDeserializer(GenericType<? extends Set<?>> type) {
        return new SetConverter(type.type());
    }

    @Override
    public JsonSerializer<Set<?>> createSerializer(Class<? extends Set<?>> type) {
        return new SetConverter(type);
    }

    @Override
    public JsonSerializer<Set<?>> createSerializer(GenericType<? extends Set<?>> type) {
        return new SetConverter(type.type());
    }

    @Override
    public Set<Class<?>> supportedTypes() {
        return Set.of(Set.class, HashSet.class);
    }

    private static final class SetConverter implements JsonConverter<Set<?>> {

        private final Type componentType;
        private JsonDeserializer<Object> deserializer;
        private JsonSerializer<Object> serializer;

        public SetConverter(Type type) {
            if (type instanceof ParameterizedType parameterizedType) {
                componentType = parameterizedType.getActualTypeArguments()[0];
            } else {
                componentType = GenericType.OBJECT;
            }
        }

        @Override
        public void serialize(Generator generator, Set<?> instance, boolean writeNulls) {
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
                serializer.serialize(generator, value, writeNulls);
                if (first) {
                    first = false;
                }
            }
            generator.writeArrayEnd();
        }

        @Override
        public Set<?> deserialize(JsonParser parser) {
            Set<Object> set = new HashSet<>();
            byte lastByte = parser.lastByte();
            if (lastByte != '[') {
                throw new JsonException("Array start expected. Found: " + Character.toString(lastByte));
            }
            lastByte = parser.nextToken();
            if (lastByte != ']') {
                set.add(Deserializers.deserialize(parser, deserializer));
                lastByte = parser.nextToken();
                while (lastByte == ',') {
                    parser.nextToken();
                    set.add(Deserializers.deserialize(parser, deserializer));
                    lastByte = parser.nextToken();
                }
                if (lastByte != ']') {
                    throw new JsonException("Array end expected, received: " + Character.toString(lastByte));
                }
            }
            return set;
        }

        @Override
        public void configure(JsonBindingConfigurator jsonBindingConfigurator) {
            deserializer = jsonBindingConfigurator.getDeserializer(componentType);
            serializer = jsonBindingConfigurator.getSerializer(componentType);
        }
    }

}
