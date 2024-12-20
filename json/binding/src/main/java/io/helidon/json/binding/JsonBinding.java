package io.helidon.json.binding;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Type;
import java.util.Map;
import java.util.function.Consumer;

import io.helidon.builder.api.RuntimeType;
import io.helidon.common.GenericType;
import io.helidon.common.types.ResolvedType;
import io.helidon.common.types.TypeName;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

@RuntimeType.PrototypedBy(JsonBindingConfig.class)
public final class JsonBinding implements RuntimeType.Api<JsonBindingConfig> {

    private static final JsonBinding DEFAULT_INSTANCE = builder().build();

    private final JsonBindingConfig config;
    private final Map<Type, JsonSerializer<?>> serializers;
    private final Map<ResolvedType, JsonSerializer<?>> serializersTypeName;
    private final Map<Type, JsonDeserializer<?>> deserializers;
    private final Map<TypeName, JsonDeserializer<?>> deserializersTypeName;

    private JsonBinding(JsonBindingConfig config) {
        this.config = config;
        this.serializers = Map.copyOf(config.serializers());
        this.serializersTypeName = Map.of();
        this.deserializers = Map.copyOf(config.deserializers());
        this.deserializersTypeName = Map.of();
    }

    public static JsonBindingConfig.Builder builder() {
        return JsonBindingConfig.builder();
    }

    public static JsonBinding create(JsonBindingConfig config) {
        return new JsonBinding(config);
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
        return (JsonSerializer<T>) serializers.get(type);
    }

    @SuppressWarnings("unchecked")
    public <T> JsonSerializer<T> getSerializer(ResolvedType type) {
        return (JsonSerializer<T>) serializersTypeName.get(type);
    }

    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(Type type) {
        return (JsonDeserializer<T>) deserializers.get(type);
    }

    @SuppressWarnings("unchecked")
    public <T> JsonDeserializer<T> getDeserializer(TypeName type) {
        return (JsonDeserializer<T>) deserializersTypeName.get(type);
    }

}
