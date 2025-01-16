package io.helidon.json.binding;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Parameter;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;

import io.helidon.common.GenericType;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

final class JsonBindingImpl implements JsonBinding, JsonBindingConfigurer {

    static final JsonBinding DEFAULT_INSTANCE = JsonBinding.builder().build();

    private final JsonBindingConfig config;
    private final Map<Class<?>, JsonSerializer<?>> identitySerializers = new HashMap<>();
    private final Map<Class<?>, JsonDeserializer<?>> identityDeserializers = new HashMap<>();
    private final Map<Class<?>, JsonBindingFactory<?>> bindingFactories = new HashMap<>();
    private final Map<Type, JsonSerializer<?>> serializers = new HashMap<>();
    private final Map<Type, JsonDeserializer<?>> deserializers = new HashMap<>();
    private final Map<Type, JsonSerializer<?>> serializersNotConfigured = new HashMap<>();
    private final Map<Type, JsonDeserializer<?>> deserializersNotConfigured = new HashMap<>();

    JsonBindingImpl(JsonBindingConfig config) {
        this.config = config;
        //Fill in serializers
        for (TypedJsonSerializer<?> serializer : config.serializers()) {
            GenericType<?> type = serializer.type();
            serializers.putIfAbsent(type, serializer);
            serializers.putIfAbsent(type.type(), serializer);
            if (type.isClass()) {
                identitySerializers.putIfAbsent(type.rawType(), serializer);
            }
        }
        //Fill in deserializers
        for (TypedJsonDeserializer<?> deserializer : config.deserializers()) {
            GenericType<?> type = deserializer.type();
            deserializers.putIfAbsent(type, deserializer);
            deserializers.putIfAbsent(type.type(), deserializer);
            if (type.isClass()) {
                identityDeserializers.putIfAbsent(type.rawType(), deserializer);
            }
        }
        //Fill in binding factories
        for (TypedJsonBindingFactory<?> bindingFactory : config.bindingFactories()) {
            bindingFactories.putIfAbsent(bindingFactory.type(), bindingFactory);
        }
    }

    @Override
    public JsonBindingConfig prototype() {
        return config;
    }

    @Override
    @SuppressWarnings("unchecked")
    public String toJson(Object obj) {
        if (obj == null) {
            return "null";
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<Object> converter = (JsonSerializer<Object>) getSerializer(obj.getClass());
            converter.toJson(generator, obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    public <T> String toJson(T obj, Class<T> type) {
        if (obj == null) {
            return "null";
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<T> converter = getSerializer(type);
            converter.toJson(generator, obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    public <T> String toJson(T obj, GenericType<T> type) {
        if (obj == null) {
            return "null";
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<T> converter = getSerializer(type);
            converter.toJson(generator, obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    public <T> T fromJson(String jsonStr, Class<T> type) {
        JsonDeserializer<T> deserializer = getDeserializer(type);
        JsonParser parser = JsonParser.createParser(jsonStr);
        parser.nextToken();
        return deserializer.fromJson(parser);
    }

    @Override
    public <T> T fromJson(String jsonStr, GenericType<T> type) {
        JsonDeserializer<T> deserializer = getDeserializer(type);
        JsonParser parser = JsonParser.createParser(jsonStr);
        parser.nextToken();
        return deserializer.fromJson(parser);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Type type) {
        if (type instanceof Class<?> clazz) {
            return (JsonDeserializer<T>) getDeserializer(clazz);
        } else if (type instanceof GenericType<?> genericType) {
            return getDeserializer(genericType);
        } else {
            return getDeserializer(GenericType.create(type));
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Class<T> type) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) identityDeserializers.get(type);
        if (deserializer != null) {
            return deserializer;
        }
        JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type);
        if (factory == null) {
            throw new IllegalStateException("Deserializer/Converter/BindingFactory for type "
                                                    + type + " is not registered.");
        }
        deserializer = factory.createDeserializer(this, type);
        deserializers.putIfAbsent(type, deserializer);
        identityDeserializers.putIfAbsent(type, deserializer);
        return deserializer;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(GenericType<?> type) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) deserializers.get(type);
        if (deserializer == null) {
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type.rawType());
            if (factory == null) {
                throw new IllegalStateException("Deserializer/Converter/BindingFactory for type "
                                                        + type + " is not registered.");
            }
            deserializer = factory.createDeserializer(this, type.type());
            deserializers.putIfAbsent(type, deserializer);
            deserializers.putIfAbsent(type.type(), deserializer);
            if (type.isClass()) {
                identityDeserializers.putIfAbsent(type.rawType(), deserializer);
            }
        }
        return deserializer;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Type type) {
        if (type instanceof Class<?> clazz) {
            return (JsonSerializer<T>) getSerializer(clazz);
        } else if (type instanceof GenericType<?> genericType) {
            return getSerializer(genericType);
        } else {
            return getSerializer(GenericType.create(type));
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Class<T> type) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) identitySerializers.get(type);
        if (serializer == null) {
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type);
            if (factory == null) {
                throw new IllegalStateException("Serializer/Converter/BindingFactory for type "
                                                        + type + " is not registered.");
            }
            serializer = factory.createSerializer(this, type);
            serializers.putIfAbsent(type, serializer);
            identitySerializers.putIfAbsent(type, serializer);
        }
        return serializer;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(GenericType<?> type) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) serializers.get(type);
        if (serializer == null) {
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type.rawType());
            if (factory == null) {
                throw new IllegalStateException("Serializer/Converter/BindingFactory for type "
                                                        + type + " is not registered.");
            }
            serializer = factory.createSerializer(this, type.type());
            serializers.putIfAbsent(type, serializer);
            serializers.putIfAbsent(type.type(), serializer);
            if (type.isClass()) {
                identitySerializers.putIfAbsent(type.rawType(), serializer);
            }
        }
        return serializer;
    }
}
