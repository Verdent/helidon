package io.helidon.json.binding;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Type;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.locks.ReentrantLock;

import io.helidon.common.GenericType;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

final class JsonBindingImpl implements JsonBinding, JsonBindingConfigurer {

    static final JsonBinding DEFAULT_INSTANCE = JsonBinding.builder().build();
    private static final JsonParser JSON_PARSER = JsonParser.createParser("");

//    private static final Queue<JsonParser> PARSERS = new ArrayDeque<>();
//    private static final Queue<JsonParser> PARSERS = new ArrayBlockingQueue<>(1);
    private static final Queue<JsonParser> PARSERS = new ConcurrentLinkedQueue<>();
    static {
        PARSERS.add(JSON_PARSER);
    }
    private static final ReentrantLock LOCK = new ReentrantLock();

    private final ThreadLocal<JsonParser> parsers = new ThreadLocal<>();

    private final JsonBindingConfig config;
    private final Map<Class<?>, JsonSerializer<?>> identitySerializers = new IdentityHashMap<>();
    private final Map<Class<?>, JsonDeserializer<?>> identityDeserializers = new IdentityHashMap<>();
    private final Map<Class<?>, JsonBindingFactory<?>> bindingFactories = new IdentityHashMap<>();
    private final Map<Type, JsonSerializer<?>> serializers = new HashMap<>();
    private final Map<Type, JsonDeserializer<?>> deserializers = new HashMap<>();

    private final Map<Type, JsonSerializer<?>> serializersNotConfigured = new HashMap<>();
    private final Map<Type, JsonDeserializer<?>> deserializersNotConfigured = new HashMap<>();
    private final ReentrantLock serNotConfiguredLock = new ReentrantLock();
    private final ReentrantLock desNotConfiguredLock = new ReentrantLock();

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
        } catch (RuntimeException e) {
            throw e;
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
            JsonSerializer<T> converter = getFinishedSerializer(type);
            converter.toJson(generator, obj);
        } catch (RuntimeException e) {
            throw e;
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
            JsonSerializer<T> converter = getFinishedSerializer(type);
            converter.toJson(generator, obj);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    @Override
    public <T> T fromJson(String jsonStr, Class<T> type) {
        JsonDeserializer<T> deserializer = getFinishedDeserializer(type);
        JsonParser parser;
        boolean isVirtual = Thread.currentThread().isVirtual();
        if (isVirtual) {
            parser = JsonParser.createParser(jsonStr);
        } else {
            parser = this.parsers.get();
            if (parser == null) {
                parser = JsonParser.createParser(jsonStr);
            } else {
                this.parsers.set(null);
                parser.reset(jsonStr.getBytes());
            }
        }
        parser.nextToken();
        T deserialized = deserializer.fromJson(parser);
        if (!isVirtual) {
            this.parsers.set(parser);
        }
        return deserialized;
//        JsonParser parser = JsonParser.createParser(jsonStr);
//        JsonParser parser = JSON_PARSER;
//        parser.reset(jsonStr.getBytes());
//        JsonParser parser = PARSERS.poll();
//        if (parser == null) {
//            System.out.println("BLEEEEEE");
//            parser = JsonParser.createParser(jsonStr);
//            parser.nextToken();
//            return deserializer.fromJson(parser);
//        } else {
//            parser.reset(jsonStr.getBytes());
//            parser.nextToken();
//            T deserialized = deserializer.fromJson(parser);
//            PARSERS.offer(parser);
//            return deserialized;
//        }
//        parser.nextToken();
//        return deserializer.fromJson(parser);
    }

    @Override
    public <T> T fromJson(String jsonStr, GenericType<T> type) {
        JsonDeserializer<T> deserializer = getFinishedDeserializer(type);
        JsonParser parser = JsonParser.createParser(jsonStr);
        parser.nextToken();
        return deserializer.fromJson(parser);
    }

    @SuppressWarnings("unchecked")
    private <T> JsonDeserializer<T> getFinishedDeserializer(Class<T> type) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) identityDeserializers.get(type);
        if (deserializer != null) {
            return deserializer;
        }
        JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type);
        if (factory == null) {
            throw new IllegalStateException("Deserializer/Converter/BindingFactory for type "
                                                    + type + " is not registered.");
        }
        BindingFactoryDeserializer<T> factoryDeserializer = factory.createDeserializer();

        deserializersNotConfigured.putIfAbsent(type, factoryDeserializer);
        factoryDeserializer.configure(this, type);
        deserializersNotConfigured.remove(type);

        deserializers.putIfAbsent(type, factoryDeserializer);
        identityDeserializers.putIfAbsent(type, factoryDeserializer);
        return factoryDeserializer;
    }

    @SuppressWarnings("unchecked")
    private <T> JsonDeserializer<T> getFinishedDeserializer(GenericType<?> type) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) deserializers.get(type);
        if (deserializer == null) {
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type.rawType());
            if (factory == null) {
                throw new IllegalStateException("Deserializer/Converter/BindingFactory for type "
                                                        + type + " is not registered.");
            }
            BindingFactoryDeserializer<T> factoryDeserializer = factory.createDeserializer();

            deserializersNotConfigured.putIfAbsent(type, factoryDeserializer);
            factoryDeserializer.configure(this, type.type());
            deserializersNotConfigured.remove(type);

            deserializers.putIfAbsent(type, factoryDeserializer);
            deserializers.putIfAbsent(type.type(), factoryDeserializer);
            if (type.isClass()) {
                identityDeserializers.putIfAbsent(type.rawType(), factoryDeserializer);
            }
            return factoryDeserializer;
        }
        return deserializer;
    }

    @SuppressWarnings("unchecked")
    private <T> JsonSerializer<T> getFinishedSerializer(Class<T> type) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) identitySerializers.get(type);
        if (serializer == null) {
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type);
            if (factory == null) {
                throw new IllegalStateException("Serializer/Converter/BindingFactory for type "
                                                        + type + " is not registered.");
            }
            BindingFactorySerializer<T> factorySerializer = factory.createSerializer();
            serializersNotConfigured.putIfAbsent(type, factorySerializer);
            factorySerializer.configure(this, type);
            serializersNotConfigured.remove(type);

            serializers.putIfAbsent(type, factorySerializer);
            identitySerializers.putIfAbsent(type, factorySerializer);
            return factorySerializer;
        }
        return serializer;
    }

    @SuppressWarnings("unchecked")
    private <T> JsonSerializer<T> getFinishedSerializer(GenericType<?> type) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) serializers.get(type);
        if (serializer == null) {
            JsonBindingFactory<T> factory = (JsonBindingFactory<T>) bindingFactories.get(type.rawType());
            if (factory == null) {
                throw new IllegalStateException("Serializer/Converter/BindingFactory for type "
                                                        + type + " is not registered.");
            }
            BindingFactorySerializer<T> factorySerializer = factory.createSerializer();
            serializersNotConfigured.putIfAbsent(type.type(), factorySerializer);
            factorySerializer.configure(this, type.type());
            serializersNotConfigured.remove(type.type());

            serializers.putIfAbsent(type, factorySerializer);
            serializers.putIfAbsent(type.type(), factorySerializer);
            if (type.isClass()) {
                identitySerializers.putIfAbsent(type.rawType(), factorySerializer);
            }
            return factorySerializer;
        }
        return serializer;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Type type) {
        return switch (type) {
            case Class<?> clazz -> (JsonDeserializer<T>) getDeserializer(clazz);
            case GenericType<?> genericType -> getDeserializer(genericType);
            case null, default -> getDeserializer(GenericType.create(type));
        };
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Class<T> type) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) deserializersNotConfigured.get(type);
        if (deserializer != null) {
            return deserializer;
        }
        return getFinishedDeserializer(type);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(GenericType<?> type) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) deserializersNotConfigured.get(type);
        if (deserializer != null) {
            return deserializer;
        }
        return getFinishedDeserializer(type);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Type type) {
        return switch (type) {
            case Class<?> clazz -> (JsonSerializer<T>) getSerializer(clazz);
            case GenericType<?> genericType -> getSerializer(genericType);
            case null, default -> getSerializer(GenericType.create(type));
        };
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Class<T> type) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) serializersNotConfigured.get(type);
        if (serializer != null) {
            return serializer;
        }
        return getFinishedSerializer(type);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(GenericType<?> type) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) serializersNotConfigured.get(type.type());
        if (serializer != null) {
            return serializer;
        }
        return getFinishedSerializer(type);
    }
}
