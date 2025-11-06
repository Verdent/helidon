package io.helidon.json.binding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import io.helidon.json.processor.JsonValue;
import io.helidon.json.processor.ReusableJsonParser;

final class JsonBindingImpl implements JsonBinding, JsonBindingConfigurator {

    public static final byte[] NULL_BYTES = "null".getBytes(StandardCharsets.UTF_8);
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

    private final ReentrantReadWriteLock serializerLock = new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock deserializerLock = new ReentrantReadWriteLock();

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
            JsonSerializer<Object> converter = (JsonSerializer<Object>) getSerializer(obj.getClass());
            converter.serialize(generator, obj, true);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    public <T> String serialize(T obj, Class<? super T> type) {
        if (obj == null) {
            return "null";
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<? super T> converter = getSerializer(type);
            converter.serialize(generator, obj, true);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    public <T> String serialize(T obj, GenericType<? super T> type) {
        if (obj == null) {
            return "null";
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<? super T> converter = getSerializer(type);
            converter.serialize(generator, obj, true);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    @SuppressWarnings("unchecked")
    public void serialize(OutputStream outputStream, Object obj) {
        if (obj == null) {
            try {
                outputStream.write(NULL_BYTES);
                return;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<Object> converter = (JsonSerializer<Object>) getSerializer(obj.getClass());
            converter.serialize(generator, obj, true);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T> void serialize(OutputStream outputStream, T obj, Class<? super T> type) {
        if (obj == null) {
            try {
                outputStream.write(NULL_BYTES);
                return;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<? super T> converter = getSerializer(type);
            converter.serialize(generator, obj, true);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T> void serialize(OutputStream outputStream, T obj, GenericType<? super T> type) {
        if (obj == null) {
            try {
                outputStream.write(NULL_BYTES);
                return;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<? super T> converter = getSerializer(type);
            converter.serialize(generator, obj, true);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T> T deserialize(String jsonStr, Class<T> type) {
        JsonDeserializer<T> deserializer = getDeserializer(type);
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
        JsonDeserializer<T> deserializer = getDeserializer(type);
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
        JsonDeserializer<T> deserializer = getDeserializer(type);
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
        JsonDeserializer<T> deserializer = getDeserializer(type);
        CachedStreamParser cachedParser = parserStreamCache.get();
        ReusableJsonParser parser = cachedParser.get();
        parser.reset(inputStream);
        parser.nextToken();
        T deserialized = Deserializers.deserialize(parser, deserializer);
        cachedParser.set(parser);
        return deserialized;
    }

    @Override
    public <T> T deserialize(JsonValue jsonValue, Class<T> type) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> T deserialize(JsonValue jsonValue, GenericType<T> type) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Type type) {
        return switch (type) {
            case Class<?> clazz -> (JsonDeserializer<T>) getDeserializer(clazz);
            case GenericType<?> genericType -> (JsonDeserializer<T>) getDeserializer(genericType);
            case null, default -> getDeserializer(GenericType.create(type));
        };
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Class<T> type) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) initialIdentityDeserializers.get(type);
        if (deserializer != null) {
            return deserializer;
        }
        try {
            deserializerLock.readLock().lock();
            deserializer = (JsonDeserializer<T>) runtimeIdentityDeserializers.get(type);
            if (deserializer != null) {
                return deserializer;
            }
        } finally {
            deserializerLock.readLock().unlock();
        }
        try {
            deserializerLock.writeLock().lock();
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
            JsonDeserializer<T> factoryDeserializer = factory.createDeserializer(type);
            runtimeDeserializers.putIfAbsent(type, factoryDeserializer);
            runtimeIdentityDeserializers.putIfAbsent(type, factoryDeserializer);
            factoryDeserializer.configure(this);
            return factoryDeserializer;
        } finally {
            deserializerLock.writeLock().unlock();
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(GenericType<T> type) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) initialDeserializers.get(type);
        if (deserializer != null) {
            return deserializer;
        }
        try {
            deserializerLock.readLock().lock();
            deserializer = (JsonDeserializer<T>) runtimeDeserializers.get(type);
            if (deserializer != null) {
                return deserializer;
            }
        } finally {
            deserializerLock.readLock().unlock();
        }
        try {
            deserializerLock.writeLock().lock();
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
            JsonDeserializer<T> factoryDeserializer = factory.createDeserializer(type);
            runtimeDeserializers.putIfAbsent(type, factoryDeserializer);
            runtimeDeserializers.putIfAbsent(type.type(), factoryDeserializer);
            factoryDeserializer.configure(this);
            if (type.isClass()) {
                runtimeIdentityDeserializers.putIfAbsent(rawType, factoryDeserializer);
            }
            return factoryDeserializer;
        } finally {
            deserializerLock.writeLock().unlock();
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Type type) {
        return switch (type) {
            case Class<?> clazz -> (JsonSerializer<T>) getSerializer(clazz);
            case GenericType<?> genericType -> (JsonSerializer<T>) getSerializer(genericType);
            case null, default -> getSerializer(GenericType.create(type));
        };
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Class<T> type) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) initialIdentitySerializers.get(type);
        if (serializer != null) {
            return serializer;
        }
        try {
            serializerLock.readLock().lock();
            serializer = (JsonSerializer<T>) runtimeIdentitySerializers.get(type);
            if (serializer != null) {
                return serializer;
            }
        } finally {
            serializerLock.readLock().unlock();
        }
        try {
            serializerLock.writeLock().lock();
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
            JsonSerializer<T> factorySerializer = factory.createSerializer(type);
            runtimeSerializers.putIfAbsent(type, factorySerializer);
            runtimeIdentitySerializers.putIfAbsent(type, factorySerializer);
            factorySerializer.configure(this);
            return factorySerializer;
        } finally {
            serializerLock.writeLock().unlock();
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(GenericType<T> type) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) initialSerializers.get(type);
        if (serializer != null) {
            return serializer;
        }
        try {
            serializerLock.readLock().lock();
            serializer = (JsonSerializer<T>) runtimeSerializers.get(type);
            if (serializer != null) {
                return serializer;
            }
        } finally {
            serializerLock.readLock().unlock();
        }
        try {
            serializerLock.writeLock().lock();
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
            JsonSerializer<T> factorySerializer = factory.createSerializer(type);
            runtimeSerializers.putIfAbsent(type, factorySerializer);
            runtimeSerializers.putIfAbsent(type.type(), factorySerializer);
            factorySerializer.configure(this);
            if (type.isClass()) {
                runtimeIdentitySerializers.putIfAbsent(rawType, factorySerializer);
            }
            return factorySerializer;
        } finally {
            serializerLock.writeLock().unlock();
        }
    }
}
