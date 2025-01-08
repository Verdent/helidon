package org.example;

import java.util.List;

import my.example.json.Configurable;
import my.example.json.Generator;
import my.example.json.JsonConverter;
import my.example.json.JsonDeserializer;
import my.example.json.JsonException;
import my.example.json.JsonObject;
import my.example.json.JsonParser;
import my.example.json.JsonSerializer;
import my.example.json.ParamTypeHelper;
import my.example.json.RuntimeJson;
import my.example.json.spi.JsonComponentProvider;

public class ClassWithStringGenerics_GeneratedConverter implements JsonConverter<ClassWithStringGenerics>, JsonComponentProvider, Configurable {

    private JsonDeserializer<Integer> deserializerInt = null;
    private JsonDeserializer<String> deserializerString = null;
    private JsonDeserializer<List<String>> deserializerCollection = null;
    private JsonSerializer<Integer> serializerInt = null;
    private JsonSerializer<String> serializerString = null;
    private JsonSerializer<List<String>> serializerCollection = null;

    @Override
    public void toJson(Generator generator, ClassWithStringGenerics instance) {
        if (instance == null) {
            generator.writeNull();
            return;
        }
        generator.writeObjectStart();
        generator.writeKey("field");
        serializerString.toJson(generator, instance.getField());
        generator.writeComma();
        generator.writeKey("collection");
        serializerCollection.toJson(generator, instance.getCollection());
        generator.writeComma();
        generator.writeKey("myInt");
        serializerInt.toJson(generator, instance.getMyInt());
        generator.writeObjectEnd();
    }

    @Override
    public ClassWithStringGenerics fromJson(JsonObject jsonObject) {
        return null;
    }

    @Override
    public ClassWithStringGenerics fromJson(JsonParser parser) {
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
        ClassWithStringGenerics generatedInstance = new ClassWithStringGenerics();
        if (lastByte != '}') {
            parser.byteRollback();
            do {
                parser.nextToken();
                int hash = parser.readStringAsHash();
                parser.nextToken();
                parser.nextToken();
                switch(hash) {
                    case 1736598119: //field
                        generatedInstance.setField(deserializerString.fromJson(parser));
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

    @Override
    public void configure(RuntimeJson runtimeJson) {
        serializerString = runtimeJson.getSerializer(String.class);
        ParamTypeHelper<List<String>> serHelperCollection = new ParamTypeHelper<>() {};
        serializerCollection = runtimeJson.getSerializer(serHelperCollection.getType());
        serializerInt = runtimeJson.getSerializer(int.class);
        deserializerString = runtimeJson.getDeserializer(String.class);
        deserializerInt = runtimeJson.getDeserializer(int.class);
        ParamTypeHelper<List<String>> desHelperCollection = new ParamTypeHelper<>() {};
        deserializerCollection = runtimeJson.getDeserializer(desHelperCollection.getType());
    }

    @Override
    public void register(RuntimeJson.Builder builder) {
        builder.registerConverter(ClassWithStringGenerics.class, this);
    }

}
