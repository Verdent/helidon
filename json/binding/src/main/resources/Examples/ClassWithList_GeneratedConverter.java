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

public class ClassWithList_GeneratedConverter implements JsonConverter<ClassWithList>, JsonComponentProvider, Configurable {

    private JsonDeserializer<List<Integer>> deserializerList = null;
    private JsonSerializer<List<Integer>> serializerList = null;

    @Override
    public void toJson(Generator generator, ClassWithList instance) {
        if (instance == null) {
            generator.writeNull();
            return;
        }
        generator.writeObjectStart();
        generator.writeKey("list");
        serializerList.toJson(generator, instance.getList());
        generator.writeObjectEnd();
    }

    @Override
    public ClassWithList fromJson(JsonObject jsonObject) {
        return null;
    }

    @Override
    public ClassWithList fromJson(JsonParser parser) {
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
        ClassWithList generatedInstance = new ClassWithList();
        if (lastByte != '}') {
            parser.byteRollback();
            do {
                parser.nextToken();
                int hash = parser.readStringAsHash();
                parser.nextToken();
                parser.nextToken();
                switch(hash) {
                    case 217798785: //list
                        generatedInstance.setList(deserializerList.fromJson(parser));
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
        ParamTypeHelper<List<Integer>> serHelperList = new ParamTypeHelper<>() {};
        serializerList = runtimeJson.getSerializer(serHelperList.getType());
        ParamTypeHelper<List<Integer>> desHelperList = new ParamTypeHelper<>() {};
        deserializerList = runtimeJson.getDeserializer(desHelperList.getType());
    }

    @Override
    public void register(RuntimeJson.Builder builder) {
        builder.registerConverter(ClassWithList.class, this);
    }

}
