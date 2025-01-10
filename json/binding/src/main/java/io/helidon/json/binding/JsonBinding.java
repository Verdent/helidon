package io.helidon.json.binding;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import io.helidon.builder.api.RuntimeType;
import io.helidon.common.GenericType;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

@RuntimeType.PrototypedBy(JsonBindingConfig.class)
public final class JsonBinding implements RuntimeType.Api<JsonBindingConfig> {

    private static final JsonBinding DEFAULT_INSTANCE = builder().build();

    private final JsonBindingConfig config;
    private final Map<Type, JsonSerializer<?>> serializers = new HashMap<>();
    private final Map<Type, JsonDeserializer<?>> deserializers = new HashMap<>();
    private final Map<Type, JsonBindingFactory<?>> bindingFactories = new HashMap<>();
    private final Map<Type, JsonSerializer<?>> serializersNotConfigured = new HashMap<>();
    private final Map<Type, JsonDeserializer<?>> deserializersNotConfigured = new HashMap<>();

    private JsonBinding(JsonBindingConfig config) {
        this.config = config;
        //Fill in serializers
        for (TypedJsonSerializer<?> serializer : config.serializers()) {
            serializers.putIfAbsent(serializer.type(), serializer);
            serializers.putIfAbsent(serializer.type().type(), serializer);
        }
        //Fill in deserializers
        for (TypedJsonDeserializer<?> deserializer : config.deserializers()) {
            deserializers.putIfAbsent(deserializer.type(), deserializer);
            deserializers.putIfAbsent(deserializer.type().type(), deserializer);
        }
        //Fill in binding factories
        for (TypedJsonBindingFactory<?> bindingFactory : config.bindingFactories()) {
            bindingFactories.putIfAbsent(bindingFactory.type(), bindingFactory);
        }
    }

    public static JsonBindingConfig.Builder builder() {
        return JsonBindingConfig.builder();
    }

    public static JsonBinding create(JsonBindingConfig config) {
        JsonBinding jsonBinding = new JsonBinding(config);
        Set<JsonConfigurable> processed = new HashSet<>();
        for (TypedJsonSerializer<?> serializer : config.serializers()) {
            if (serializer instanceof JsonConfigurable configurable) {
                configurable.configure(jsonBinding);
                processed.add(configurable);
            }
        }
        for (TypedJsonDeserializer<?> deserializer : config.deserializers()) {
            if (deserializer instanceof JsonConfigurable configurable
                    && !processed.contains(deserializer)) {
                configurable.configure(jsonBinding);
            }
        }
        return jsonBinding;
    }

    static JsonBinding create(Consumer<JsonBindingConfig.Builder> consumer) {
        JsonBindingConfig.Builder builder = builder().update(consumer);
        return create(builder.buildPrototype());
    }

    public static String serialize(Object obj) {
        return DEFAULT_INSTANCE.toJson(obj);
    }

    public static String serialize(Object obj, GenericType<?> type) {
        return DEFAULT_INSTANCE.toJson(obj, type);
    }

    public static <T> T deserialize(String jsonStr, Class<T> type) {
        return DEFAULT_INSTANCE.fromJson(jsonStr, (Type) type);
    }

    public static <T> T deserialize(String jsonStr, GenericType<T> type) {
        return DEFAULT_INSTANCE.fromJson(jsonStr, type);
    }

//    public static <T> T deserialize(JsonParser parser, Class<T> type) {
//        return DEFAULT_INSTANCE.fromJson(parser, type);
//    }
//
//    public static <T> T deserialize(JsonParser parser, GenericType<T> type) {
//        return DEFAULT_INSTANCE.fromJson(parser, type);
//    }
//
//    public static <T> T deserialize(JsonObject object, GenericType<T> type) {
//        return DEFAULT_INSTANCE.fromJson(object, type);
//    }


    public String toJson(Object obj) {
        return toJson(obj, obj.getClass());
    }

    @SuppressWarnings("unchecked")
    public <T> String toJson(Object obj, Type type) {
        if (obj == null) {
            return "null";
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (Generator generator = Generator.create(outputStream)) {
            JsonSerializer<T> converter = getSerializer(type);
            converter.toJson(generator, (T) obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString();
    }

    public <T> T fromJson(String jsonStr, Class<T> type) {
        return fromJson(jsonStr, (Type) type);
    }

    public <T> T fromJson(String jsonStr, Type type) {
        //        JsonParser parser = this.parser.get();
        //        if (parser == null) {
        //            parser = JsonParser.createParser(jsonStr);
        //            this.parser.set(parser);
        //        } else {
        //            parser.reset(jsonStr.getBytes());
        //        }
        JsonParser parser = JsonParser.createParser(jsonStr);
        parser.nextToken();
        return fromJson(parser, type);
    }

    public <T> T fromJson(JsonParser parser, Class<T> type) {
        JsonDeserializer<T> deserializer = getDeserializer(type);
        return deserializer.fromJson(parser);
    }

    public <T> T fromJson(JsonParser parser, Type type) {
        JsonDeserializer<T> deserializer = getDeserializer(type);
        return deserializer.fromJson(parser);
    }

    @Override
    public JsonBindingConfig prototype() {
        return config;
    }

    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(Type type) {
        JsonSerializer<T> serializer = (JsonSerializer<T>) serializers.get(type);

        if (serializer == null) {
            JsonBindingFactory<T> factory;
            Type toProcess;
            if (type instanceof GenericType<?> genericType) {
                factory = (JsonBindingFactory<T>) bindingFactories.get(genericType.rawType());
                toProcess = genericType.type();
            } else {
                factory = (JsonBindingFactory<T>) bindingFactories.get(type);
                toProcess = type;
            }
            if (factory == null) {
                throw new IllegalStateException("Serializer/Converter/BindingFactory for type "
                                                        + type + " is not registered.");
            }
            serializer = factory.createSerializer(this, toProcess);
            serializers.putIfAbsent(type, serializer);
            serializers.putIfAbsent(toProcess, serializer);
        }
        return serializer;
    }

    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Type type) {
        JsonDeserializer<T> deserializer = (JsonDeserializer<T>) deserializers.get(type);

        if (deserializer == null) {
            JsonBindingFactory<T> factory;
            Type toProcess;
            if (type instanceof GenericType<?> genericType) {
                factory = (JsonBindingFactory<T>) bindingFactories.get(genericType.rawType());
                toProcess = genericType.type();
            } else {
                factory = (JsonBindingFactory<T>) bindingFactories.get(type);
                toProcess = type;
            }
            if (factory == null) {
                throw new IllegalStateException("Deserializer/Converter/BindingFactory for type "
                                                        + type + " is not registered.");
            }
            deserializer = factory.createDeserializer(this, toProcess);
            deserializers.putIfAbsent(type, deserializer);
            deserializers.putIfAbsent(toProcess, deserializer);
        }
        return deserializer;
    }

}
