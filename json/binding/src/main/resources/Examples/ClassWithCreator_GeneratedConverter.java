package org.example;

import my.example.json.Configurable;
import my.example.json.Generator;
import my.example.json.JsonConverter;
import my.example.json.JsonDeserializer;
import my.example.json.JsonException;
import my.example.json.JsonObject;
import my.example.json.JsonParser;
import my.example.json.JsonSerializer;
import my.example.json.RuntimeJson;
import my.example.json.spi.JsonComponentProvider;

public class ClassWithCreator_GeneratedConverter implements JsonConverter<ClassWithCreator>, JsonComponentProvider, Configurable {

    private JsonDeserializer<Integer> deserializerInt = null;
    private JsonDeserializer<String> deserializerString = null;
    private JsonSerializer<Integer> serializerInt = null;
    private JsonSerializer<String> serializerString = null;

    @Override
    public void toJson(Generator generator, ClassWithCreator instance) {
        if (instance == null) {
            generator.writeNull();
            return;
        }
        generator.writeObjectStart();
        generator.writeKey("givenName");
        serializerString.toJson(generator, instance.getGivenName());
        generator.writeComma();
        generator.writeKey("sureName");
        serializerString.toJson(generator, instance.getSureName());
        generator.writeComma();
        generator.writeKey("age");
        serializerInt.toJson(generator, instance.getAge());
        generator.writeObjectEnd();
    }

    @Override
    public ClassWithCreator fromJson(JsonObject jsonObject) {
        return null;
    }

    @Override
    public ClassWithCreator fromJson(JsonParser parser) {
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
        String givenName_ = null;
        String sureName_ = null;
        int age_ = 0;
        if (lastByte != '}') {
            parser.byteRollback();
            do {
                parser.nextToken();
                int hash = parser.readStringAsHash();
                parser.nextToken();
                parser.nextToken();
                switch(hash) {
                    case -441165789: //sureName
                        sureName_ = deserializerString.fromJson(parser);
                        break;
                    case 742476188: //age
                        age_ = deserializerInt.fromJson(parser);
                        break;
                    case 235550645: //givenName
                        givenName_ = deserializerString.fromJson(parser);
                        break;
                    default:
                        parser.skip();
                }
                lastByte = parser.nextToken();
            } while(lastByte == ',');
        }
        ClassWithCreator generatedInstance = new ClassWithCreator(givenName_, sureName_);
        generatedInstance.setAge(age_);
        return generatedInstance;
    }

    @Override
    public void configure(RuntimeJson runtimeJson) {
        serializerString = runtimeJson.getSerializer(String.class);
        serializerInt = runtimeJson.getSerializer(int.class);
        deserializerString = runtimeJson.getDeserializer(String.class);
        deserializerInt = runtimeJson.getDeserializer(int.class);
    }

    @Override
    public void register(RuntimeJson.Builder builder) {
        builder.registerConverter(ClassWithCreator.class, this);
    }

}
