package io.helidon.json.binding.factories;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.BindingFactoryConverter;
import io.helidon.json.binding.BindingFactoryDeserializer;
import io.helidon.json.binding.BindingFactorySerializer;
import io.helidon.json.binding.Deserializers;
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
class MapBindingFactory implements TypedJsonBindingFactory<Map<?, ?>> {

    @Override
    public Set<Class<?>> supportedTypes() {
        return Set.of(Map.class, HashMap.class);
    }

    @Override
    public BindingFactoryDeserializer<Map<?, ?>> createDeserializer(Type type) {
        return new MapConverter(type);
    }

    @Override
    public BindingFactorySerializer<Map<?, ?>> createSerializer(Type type) {
        return new MapConverter(type);
    }

    private static final class MapConverter implements BindingFactoryConverter<Map<?, ?>> {

        private final Type keyType;
        private final Type valueType;
        private JsonDeserializer<Object> keyDeserializer;
        private JsonDeserializer<Object> valueDeserializer;
        private JsonSerializer<Object> keySerializer;
        private JsonSerializer<Object> valueSerializer;

        public MapConverter(Type type) {
            if (type instanceof ParameterizedType parameterizedType) {
                keyType = parameterizedType.getActualTypeArguments()[0];
                valueType = parameterizedType.getActualTypeArguments()[1];
            } else {
                keyType = GenericType.OBJECT;
                valueType = GenericType.OBJECT;
            }
        }

        @Override
        public void serialize(Generator generator, Map<?, ?> instance, boolean writeNulls) {
            if (instance == null) {
                generator.writeNull();
                return;
            }
            generator.writeObjectStart();
            boolean first = true;
            for (var entry : instance.entrySet()) {
                Object key = entry.getKey();
                Object value = entry.getValue();
                if (!first) {
                    generator.writeComma();
                }
                keySerializer.serialize(generator, key, writeNulls);
                generator.writeColon();
                if (value == null) {
                    valueSerializer.serializeNull(generator);
                } else {
                    valueSerializer.serialize(generator, value, writeNulls);
                }
                if (first) {
                    first = false;
                }
            }
            generator.writeObjectEnd();
        }

        @Override
        public Map<?, ?> deserialize(JsonParser parser) {
            Map<Object, Object> map = new HashMap<>();
            byte lastByte = parser.lastByte();
            if (lastByte != '{') {
                throw new JsonException("Map start '{' expected. Found: " + Character.toString(lastByte));
            }
            lastByte = parser.nextToken();
            if (lastByte != '}') {
                if (lastByte != '"') {
                    throw new JsonException("Map key expected. Found: " + Character.toString(lastByte));
                }
                Object key = Deserializers.deserialize(parser, keyDeserializer);
                lastByte = parser.nextToken();
                if (lastByte != ':') {
                    throw new JsonException("Key value separator ':' expected. Found: " + Character.toString(lastByte));
                }
                parser.nextToken();
                Object value = Deserializers.deserialize(parser, valueDeserializer);
                map.put(key, value);
                lastByte = parser.nextToken();
                while (lastByte == ',') {
                    parser.nextToken();
                    key = Deserializers.deserialize(parser, keyDeserializer);
                    lastByte = parser.nextToken();
                    if (lastByte != ':') {
                        throw new JsonException("Key value separator ':' expected. Found: " + Character.toString(lastByte));
                    }
                    parser.nextToken();
                    value = Deserializers.deserialize(parser, valueDeserializer);
                    map.put(key, value);
                    lastByte = parser.nextToken();
                }
                if (lastByte != '}') {
                    throw new JsonException("Map key expected. Found: " + Character.toString(lastByte));
                }
            }
            return map;
        }

        @Override
        public void configure(JsonBindingConfigurer jsonBindingConfigurer, JsonContext jsonContext) {
            keyDeserializer = jsonBindingConfigurer.getDeserializer(keyType);
            valueDeserializer = jsonBindingConfigurer.getDeserializer(valueType);
            keySerializer = jsonBindingConfigurer.getSerializer(keyType);
            valueSerializer = jsonBindingConfigurer.getSerializer(valueType);
        }
    }


}
