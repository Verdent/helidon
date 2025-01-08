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

public class OtherBean_GeneratedConverter implements JsonConverter<OtherBean>, JsonComponentProvider, Configurable {

    private JsonDeserializer<String> deserializerString = null;
    private JsonSerializer<String> serializerString = null;

    @Override
    public void toJson(Generator generator, OtherBean instance) {
        if (instance == null) {
            generator.writeNull();
            return;
        }
        generator.writeObjectStart();
        generator.writeKey("otherString");
        serializerString.toJson(generator, instance.getOtherString());
        generator.writeObjectEnd();
    }

    @Override
    public OtherBean fromJson(JsonObject jsonObject) {
        return null;
    }

    @Override
    public OtherBean fromJson(JsonParser parser) {
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
        OtherBean generatedInstance = new OtherBean();
        if (lastByte != '}') {
            parser.byteRollback();
            do {
                parser.nextToken();
                int hash = parser.readStringAsHash();
                parser.nextToken();
                parser.nextToken();
                switch(hash) {
                    case -1654827544: //otherString
                        generatedInstance.setOtherString(deserializerString.fromJson(parser));
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
        deserializerString = runtimeJson.getDeserializer(String.class);
    }

    @Override
    public void register(RuntimeJson.Builder builder) {
        builder.registerConverter(OtherBean.class, this);
    }

}
