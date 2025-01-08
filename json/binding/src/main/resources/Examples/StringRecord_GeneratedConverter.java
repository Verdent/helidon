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

public class StringRecord_GeneratedConverter implements JsonConverter<StringRecord>, JsonComponentProvider, Configurable {

    private JsonDeserializer<Integer> deserializerInt = null;
    private JsonDeserializer<String> deserializerString = null;
    private JsonSerializer<Integer> serializerInt = null;
    private JsonSerializer<String> serializerString = null;

    @Override
    public void toJson(Generator generator, StringRecord instance) {
        if (instance == null) {
            generator.writeNull();
            return;
        }
        generator.writeObjectStart();
        generator.writeKey("stringProperty");
        serializerString.toJson(generator, instance.myProperty());
        generator.writeComma();
        generator.writeKey("value");
        serializerInt.toJson(generator, instance.value());
        generator.writeObjectEnd();
    }

    @Override
    public StringRecord fromJson(JsonObject jsonObject) {
        return null;
    }

    @Override
    public StringRecord fromJson(JsonParser parser) {
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
        String stringProperty_ = null;
        int value_ = 0;
        if (lastByte != '}') {
            parser.byteRollback();
            do {
                parser.nextToken();
                int hash = parser.readStringAsHash();
                parser.nextToken();
                parser.nextToken();
                switch(hash) {
                    case 1113510858: //value
                        value_ = deserializerInt.fromJson(parser);
                        break;
                    case -2006475679: //stringProperty
                        stringProperty_ = deserializerString.fromJson(parser);
                        break;
                    default:
                        parser.skip();
                }
                lastByte = parser.nextToken();
            } while(lastByte == ',');
        }
        StringRecord generatedInstance = new StringRecord(stringProperty_, value_);
        return generatedInstance;
    }

    @Override
    public void configure(RuntimeJson runtimeJson) {
        serializerString = runtimeJson.getSerializer(String.class);
        serializerInt = runtimeJson.getSerializer(int.class);
        deserializerInt = runtimeJson.getDeserializer(int.class);
        deserializerString = runtimeJson.getDeserializer(String.class);
    }

    @Override
    public void register(RuntimeJson.Builder builder) {
        builder.registerConverter(StringRecord.class, this);
    }

}
