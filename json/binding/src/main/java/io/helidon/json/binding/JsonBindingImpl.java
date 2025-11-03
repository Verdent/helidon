package io.helidon.json.binding;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import io.helidon.common.GenericType;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.ReusableJsonParser;

final class JsonBindingImpl implements JsonBinding, JsonBindingConfigurer {

    private static final JsonContext EMPTY_CONTEXT = JsonContext.create();
    private final ThreadLocal<CachedParser> parserCache = ThreadLocal.withInitial(CachedParser::new);
    private final ThreadLocal<CachedStreamParser> parserStreamCache = ThreadLocal.withInitial(CachedStreamParser::new);

    private final JsonBindingConfig config;
    private final Map<Class<?>, JsonSerializer<?>> initialIdentitySerializers = new IdentityHashMap<>();
    private final Map<Class<?>, JsonDeserializer<?>> initialIdentityDeserializers = new IdentityHashMap<>();
    private final Map<Type, JsonSerializer<?>> initialSerializers = new HashMap<>();
    private final Map<Type, JsonDeserializer<?>> initialDeserializers = new HashMap<>();
    private final Map<Class<?>, JsonBindingFactory<?>> bindingFactories = new IdentityHashMap<>();

    private final Map<Class<?>, JsonSerializer<?>> runtimeIdentitySerializers = new IdentityHashMap<>();
    private final Map<Class<?>, JsonDeserializer<?>> runtimeIdentityDeserializers = new IdentityHashMap<>();
    private final Map<Type, JsonSerializer<?>> runtimeSerializers = new HashMap<>();
    private final Map<Type, JsonDeserializer<?>> runtimeDeserializers = new HashMap<>();

    private final Map<Type, JsonSerializer<?>> serializersNotConfigured = new HashMap<>();
    private final Map<Type, JsonDeserializer<?>> deserializersNotConfigured = new HashMap<>();
    private final ReentrantReadWriteLock serNotConfiguredLock = new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock desNotConfiguredLock = new ReentrantReadWriteLock();

    JsonBindingImpl(JsonBindingConfig config) {
        this.config = config;
        //Fill in serializers
        for (TypedJsonSerializer<?> serializer : config.serializers()) {
            GenericType<?> type = serializer.type();
            initialSerializers.putIfAbsent(type, serializer);
            initialSerializers.putIfAbsent(type.type(), serializer);
            if (type.isClass()) {
                initialIdentitySerializers.putIfAbsent(type.rawType(), serializer);
            }
        }
        //Fill in deserializers
        for (TypedJsonDeserializer<?> deserializer : config.deserializers()) {
            GenericType<?> type = deserializer.type();
            initialDeserializers.putIfAbsent(type, deserializer);
            initialDeserializers.putIfAbsent(type.type(), deserializer);
            if (type.isClass()) {
                initialIdentityDeserializers.putIfAbsent(type.rawType(), deserializer);
            }
        }
        //Fill in binding factories
        for (TypedJsonBindingFactory<?> bindingFactory : config.bindingFactories()) {
            bindingFactory.supportedTypes().forEach(type -> bindingFactories.putIfAbsent(type, bindingFactory));
        }
    }

    @Override
    public JsonBindingConfig prototype() {
        return config;
    }

    @Override
    @SuppressWarnings("unchecked")
    public String serialize(Object obj) {
        if (obj == null) {
            return "null";
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<Object> converter = (JsonSerializer<Object>) getFinishedSerializer(obj.getClass(), EMPTY_CONTEXT);
            converter.serialize(generator, obj, true);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    public <T> String serialize(T obj, Class<T> type) {
        if (obj == null) {
            return "null";
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<T> converter = getFinishedSerializer(type, EMPTY_CONTEXT);
            converter.serialize(generator, obj, true);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    public <T> String serialize(T obj, GenericType<T> type) {
        if (obj == null) {
            return "null";
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<T> converter = getFinishedSerializer(type, EMPTY_CONTEXT);
            converter.serialize(generator, obj, true);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    public <T> T deserialize(String jsonStr, Class<T> type) {
        JsonDeserializer<T> deserializer = getFinishedDeserializer(type, EMPTY_CONTEXT);
        CachedParser cachedParser = parserCache.get();
        ReusableJsonParser parser = cachedParser.get();
        parser.reset(jsonStr.getBytes(StandardCharsets.UTF_8));
        parser.nextToken();
        T deserialized = Deserializers.deserialize(parser, deserializer);
        cachedParser.set(parser);
        return deserialized;
    }

    @Override
    public <T> T deserialize(String jsonStr, GenericType<T> type) {
        JsonDeserializer<T> deserializer = getFinishedDeserializer(type, EMPTY_CONTEXT);
        CachedParser cachedParser = parserCache.get();
        ReusableJsonParser parser = cachedParser.get();
        parser.reset(jsonStr.getBytes(StandardCharsets.UTF_8));
        parser.nextToken();
        T deserialized = Deserializers.deserialize(parser, deserializer);
        cachedParser.set(parser);
        return deserialized;
    }

    @Override
    public <T> T deserialize(InputStream inputStream, Class<T> type) {
        JsonDeserializer<T> deserializer = getFinishedDeserializer(type, EMPTY_CONTEXT);
        CachedStreamParser cachedParser = parserStreamCache.get();
        ReusableJsonParser parser = cachedParser.get();
        parser.reset(inputStream);
        parser.nextToken();
        T deserialized = Deserializers.deserialize(parser, deserializer);
        cachedParser.set(parser);
        return deserialized;
    }

    @Override
    public <T> T deserialize(InputStream inputStream, GenericType<T> type) {
        JsonDeserializer<T> deserializer = getFinishedDeserializer(type, EMPTY_CONTEXT);
        CachedStreamParser cachedParser = parserStreamCache.get();
        ReusableJsonParser parser = cachedParser.get();
        parser.reset(inputStream);
        parser.nextToken();
        T deserialized = Deserializers.deserialize(parser, deserializer);
        cachedParser.set(parser);
        return deserialized;
    }

    @SuppressWarnings("unchecked")
    private <T> JsonDeserializer<T> getFinishedDeserializer(Class<T> type, JsonContext jsonContext) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) initialIdentityDeserializers.get(type);
        if (deserializer != null) {
            return deserializer;
        }
        try {
            desNotConfiguredLock.readLock().lock();
            deserializer = (JsonDeserializer<T>) runtimeIdentityDeserializers.get(type);
            if (deserializer != null) {
                return deserializer;
            }
        } finally {
            desNotConfiguredLock.readLock().unlock();
        }
        try {
            desNotConfiguredLock.writeLock().lock();
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type);
            if (factory == null) {
                if (type.isArray()) {
                    factory = (JsonBindingFactory<T>) bindingFactories.get(Array.class);
                }
                if (factory == null) {
                    throw new IllegalStateException("Deserializer/Converter/BindingFactory for type "
                                                            + type + " is not registered.");
                }
            }
            BindingFactoryDeserializer<T> factoryDeserializer = factory.createDeserializer(type);
            deserializersNotConfigured.putIfAbsent(type, factoryDeserializer);
            factoryDeserializer.configure(this, jsonContext);
            deserializersNotConfigured.remove(type);

            runtimeDeserializers.putIfAbsent(type, factoryDeserializer);
            runtimeIdentityDeserializers.putIfAbsent(type, factoryDeserializer);
            return factoryDeserializer;
        } finally {
            desNotConfiguredLock.writeLock().unlock();
        }
    }

    @SuppressWarnings("unchecked")
    private <T> JsonDeserializer<T> getFinishedDeserializer(GenericType<?> type, JsonContext jsonContext) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) initialDeserializers.get(type);
        if (deserializer != null) {
            return deserializer;
        }
        try {
            desNotConfiguredLock.readLock().lock();
            deserializer = (JsonDeserializer<T>) runtimeDeserializers.get(type);
            if (deserializer != null) {
                return deserializer;
            }
        } finally {
            desNotConfiguredLock.readLock().unlock();
        }
        try {
            desNotConfiguredLock.writeLock().lock();
            Class<?> rawType = type.rawType();
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(rawType);
            if (factory == null) {
                if (rawType.isArray()) {
                    factory = (JsonBindingFactory<T>) bindingFactories.get(Array.class);
                }
                if (factory == null) {
                    throw new IllegalStateException("Deserializer/Converter/BindingFactory for type "
                                                            + type + " is not registered.");
                }
            }
            BindingFactoryDeserializer<T> factoryDeserializer = factory.createDeserializer(type.type());

            deserializersNotConfigured.putIfAbsent(type, factoryDeserializer);
            factoryDeserializer.configure(this, jsonContext);
            deserializersNotConfigured.remove(type);

            runtimeDeserializers.putIfAbsent(type, factoryDeserializer);
            runtimeDeserializers.putIfAbsent(type.type(), factoryDeserializer);
            if (type.isClass()) {
                runtimeIdentityDeserializers.putIfAbsent(rawType, factoryDeserializer);
            }
            return factoryDeserializer;
        } finally {
            desNotConfiguredLock.writeLock().unlock();
        }
    }

    @SuppressWarnings("unchecked")
    private <T> JsonSerializer<T> getFinishedSerializer(Class<T> type, JsonContext jsonContext) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) initialIdentitySerializers.get(type);
        if (serializer != null) {
            return serializer;
        }
        try {
            serNotConfiguredLock.readLock().lock();
            serializer = (JsonSerializer<T>) runtimeIdentitySerializers.get(type);
            if (serializer != null) {
                return serializer;
            }
        } finally {
            serNotConfiguredLock.readLock().unlock();
        }
        try {
            serNotConfiguredLock.writeLock().lock();
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type);
            if (factory == null) {
                if (type.isArray()) {
                    factory = (JsonBindingFactory<T>) bindingFactories.get(Array.class);
                } else if (List.class.isAssignableFrom(type)) {
                    factory = (JsonBindingFactory<T>) bindingFactories.get(List.class);
                } else if (Map.class.isAssignableFrom(type)) {
                    factory = (JsonBindingFactory<T>) bindingFactories.get(Map.class);
                } else if (Set.class.isAssignableFrom(type)) {
                    factory = (JsonBindingFactory<T>) bindingFactories.get(Set.class);
                }
                if (factory == null) {
                    throw new IllegalStateException("Serializer/Converter/BindingFactory for type "
                                                            + type + " is not registered.");
                }
            }
            BindingFactorySerializer<T> factorySerializer = factory.createSerializer(type);
            serializersNotConfigured.putIfAbsent(type, factorySerializer);
            factorySerializer.configure(this, jsonContext);
            serializersNotConfigured.remove(type);

            runtimeSerializers.putIfAbsent(type, factorySerializer);
            runtimeIdentitySerializers.putIfAbsent(type, factorySerializer);
            return factorySerializer;
        } finally {
            serNotConfiguredLock.writeLock().unlock();
        }
    }

    @SuppressWarnings("unchecked")
    private <T> JsonSerializer<T> getFinishedSerializer(GenericType<?> type, JsonContext jsonContext) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) initialSerializers.get(type);
        if (serializer != null) {
            return serializer;
        }
        try {
            serNotConfiguredLock.readLock().lock();
            serializer = (JsonSerializer<T>) runtimeSerializers.get(type);
            if (serializer != null) {
                return serializer;
            }
        } finally {
            serNotConfiguredLock.readLock().unlock();
        }
        try {
            serNotConfiguredLock.writeLock().lock();
            Class<?> rawType = type.rawType();
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(rawType);
            if (factory == null) {
                if (rawType.isArray()) {
                    factory = (JsonBindingFactory<T>) bindingFactories.get(Array.class);
                }
                if (factory == null) {
                    throw new IllegalStateException("Serializer/Converter/BindingFactory for type "
                                                            + type + " is not registered.");
                }
            }
            BindingFactorySerializer<T> factorySerializer = factory.createSerializer(type.type());
            serializersNotConfigured.putIfAbsent(type.type(), factorySerializer);
            factorySerializer.configure(this, jsonContext);
            serializersNotConfigured.remove(type.type());

            runtimeSerializers.putIfAbsent(type, factorySerializer);
            runtimeSerializers.putIfAbsent(type.type(), factorySerializer);
            if (type.isClass()) {
                runtimeIdentitySerializers.putIfAbsent(rawType, factorySerializer);
            }
            return factorySerializer;
        } finally {
            serNotConfiguredLock.writeLock().unlock();
        }
    }

    @Override
    public <T> JsonDeserializer<T> getDeserializer(Type type) {
        return getDeserializer(type, EMPTY_CONTEXT);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Type type, JsonContext jsonContext) {
        return switch (type) {
            case Class<?> clazz -> (JsonDeserializer<T>) getDeserializer(clazz, jsonContext);
            case GenericType<?> genericType -> getDeserializer(genericType, jsonContext);
            case null, default -> getDeserializer(GenericType.create(type), jsonContext);
        };
    }

    @Override
    public <T> JsonDeserializer<T> getDeserializer(Class<T> type) {
        return getDeserializer(type, EMPTY_CONTEXT);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Class<T> type, JsonContext jsonContext) {
        try {
            desNotConfiguredLock.readLock().lock();
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) deserializersNotConfigured.get(type);
        if (deserializer != null) {
            return deserializer;
        }
        } finally {
            desNotConfiguredLock.readLock().unlock();
        }
        return getFinishedDeserializer(type, jsonContext);
    }

    @Override
    public <T> JsonDeserializer<T> getDeserializer(GenericType<?> type) {
        return getDeserializer(type, EMPTY_CONTEXT);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(GenericType<?> type, JsonContext jsonContext) {
        try {
            desNotConfiguredLock.readLock().lock();
            JsonDeserializer<T> deserializer = (JsonDeserializer<T>) deserializersNotConfigured.get(type);
            if (deserializer != null) {
                return deserializer;
            }
        } finally {
            desNotConfiguredLock.readLock().unlock();
        }
        return getFinishedDeserializer(type, jsonContext);
    }

    @Override
    public <T> JsonSerializer<T> getSerializer(Type type) {
        return getSerializer(type, EMPTY_CONTEXT);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Type type, JsonContext jsonContext) {
        return switch (type) {
            case Class<?> clazz -> (JsonSerializer<T>) getSerializer(clazz);
            case GenericType<?> genericType -> getSerializer(genericType);
            case null, default -> getSerializer(GenericType.create(type));
        };
    }

    @Override
    public <T> JsonSerializer<T> getSerializer(Class<T> type) {
        return getSerializer(type, EMPTY_CONTEXT);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Class<T> type, JsonContext jsonContext) {
        try {
            serNotConfiguredLock.readLock().lock();
            JsonSerializer<T> serializer = (JsonSerializer<T>) serializersNotConfigured.get(type);
            if (serializer != null) {
                return serializer;
            }
        } finally {
            serNotConfiguredLock.readLock().unlock();
        }
        return getFinishedSerializer(type, jsonContext);
    }

    @Override
    public <T> JsonSerializer<T> getSerializer(GenericType<?> type) {
        return getSerializer(type, EMPTY_CONTEXT);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(GenericType<?> type, JsonContext jsonContext) {
        try {
            serNotConfiguredLock.readLock().lock();
            JsonSerializer<T> serializer = (JsonSerializer<T>) serializersNotConfigured.get(type.type());
            if (serializer != null) {
                return serializer;
            }
        } finally {
            serNotConfiguredLock.readLock().unlock();
        }
        return getFinishedSerializer(type, jsonContext);
    }
}
