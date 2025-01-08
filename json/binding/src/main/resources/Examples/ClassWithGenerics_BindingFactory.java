package org.example;

import java.lang.reflect.ParameterizedType;
import java.util.List;

import my.example.json.BindingFactory;
import my.example.json.Generator;
import my.example.json.GenericsHelper;
import my.example.json.JsonConverter;
import my.example.json.JsonDeserializer;
import my.example.json.JsonException;
import my.example.json.JsonObject;
import my.example.json.JsonParser;
import my.example.json.JsonSerializer;
import my.example.json.RuntimeJson;
import my.example.json.spi.JsonComponentProvider;

public final class ClassWithGenerics_BindingFactory<T> implements BindingFactory<ClassWithGenerics<T>>, JsonComponentProvider {

    @Override
    public JsonDeserializer<ClassWithGenerics<T>> createDeserializer(RuntimeJson runtimeJson, ParameterizedType createdType) {
        return new ClassWithGenericsConverter(runtimeJson, createdType);
    }

    @Override
    public JsonSerializer<ClassWithGenerics<T>> createSerializer(RuntimeJson runtimeJson, ParameterizedType createdType) {
        return new ClassWithGenericsConverter(runtimeJson, createdType);
    }

    @Override
    public void register(RuntimeJson.Builder builder) {
        builder.registerBindingFactory(ClassWithGenerics.class, this);
    }

    public static final class ClassWithGenericsConverter<T> implements JsonConverter<ClassWithGenerics<T>> {

        private JsonDeserializer<T> deserializerT = null;
        private JsonDeserializer<Integer> deserializerInt = null;
        private JsonDeserializer<List<T>> deserializerCollection = null;
        private JsonSerializer<T> serializerT = null;
        private JsonSerializer<Integer> serializerInt = null;
        private JsonSerializer<List<T>> serializerCollection = null;

        private ClassWithGenericsConverter(RuntimeJson runtimeJson, ParameterizedType createdType) {
            serializerT = runtimeJson.getSerializer(createdType.getActualTypeArguments()[0]);
            serializerCollection = runtimeJson.getSerializer(GenericsHelper.createParamType(List.class, createdType.getActualTypeArguments()[0]));
            serializerInt = runtimeJson.getSerializer(int.class);
            deserializerT = runtimeJson.getDeserializer(createdType.getActualTypeArguments()[0]);
            deserializerInt = runtimeJson.getDeserializer(int.class);
            deserializerCollection = runtimeJson.getDeserializer(GenericsHelper.createParamType(List.class, createdType.getActualTypeArguments()[0]));
        }

        @Override
        public void toJson(Generator generator, ClassWithGenerics<T> instance) {
            if (instance == null) {
                generator.writeNull();
                return;
            }
            generator.writeObjectStart();
            generator.writeKey("field");
            serializerT.toJson(generator, instance.getField());
            generator.writeComma();
            generator.writeKey("collection");
            serializerCollection.toJson(generator, instance.getCollection());
            generator.writeComma();
            generator.writeKey("myInt");
            serializerInt.toJson(generator, instance.getMyInt());
            generator.writeObjectEnd();
        }

        @Override
        public ClassWithGenerics<T> fromJson(JsonObject jsonObject) {
            return null;
        }

        @Override
        public ClassWithGenerics<T> fromJson(JsonParser parser) {
            if (parser.checkNull()) {
                return null;
            }
            byte lastByte = parser.lastByte();
            if (lastByte != '{') {
                throw new JsonException("Object start expected. Found: " + Character.toString(lastByte));
            }
            lastByte = parser.readNextByte();
            if (lastByte != '"') {
                parser.byteRollback();
                lastByte = parser.nextToken();
            }
            ClassWithGenerics<T> generatedInstance = new ClassWithGenerics<T>();
            if (lastByte != '}') {
                parser.byteRollback();
                do {
                    parser.nextToken();
                    int hash = parser.readStringAsHash();
                    parser.nextToken();
                    parser.nextToken();
                    switch(hash) {
                        case 1736598119: //field
                            generatedInstance.setField(deserializerT.fromJson(parser));
                            break;
                        case -558587812: //myInt
                            generatedInstance.setMyInt(deserializerInt.fromJson(parser));
                            break;
                        case 2142078097: //collection
                            generatedInstance.setCollection(deserializerCollection.fromJson(parser));
                            break;
                        default:
                            parser.skip();
                    }
                    lastByte = parser.nextToken();
                } while(lastByte == ',');
            }
            return generatedInstance;
        }

    }

}
