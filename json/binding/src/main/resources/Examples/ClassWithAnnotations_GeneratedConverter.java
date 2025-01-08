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
import my.example.json.converters.StringConverter;
import my.example.json.spi.JsonComponentProvider;

public class ClassWithAnnotations_GeneratedConverter implements JsonConverter<ClassWithAnnotations>, JsonComponentProvider, Configurable {

    private static final StringConverter THIRD_DESERIALIZER = new StringConverter();

    private JsonDeserializer<String> deserializerString = null;
    private JsonSerializer<String> serializerString = null;

    @Override
    public void toJson(Generator generator, ClassWithAnnotations instance) {
        if (instance == null) {
            generator.writeNull();
            return;
        }
        generator.writeObjectStart();
        generator.writeKey("otherName");
        serializerString.toJson(generator, instance.getName());
        generator.writeComma();
        generator.writeKey("second");
        serializerString.toJson(generator, instance.getSecond());
        generator.writeComma();
        generator.writeKey("third");
        serializerString.toJson(generator, instance.third);
        generator.writeComma();
        generator.writeKey("fourth");
        serializerString.toJson(generator, instance.fourth);
        generator.writeObjectEnd();
    }

    @Override
    public ClassWithAnnotations fromJson(JsonObject jsonObject) {
        return null;
    }

    @Override
    public ClassWithAnnotations fromJson(JsonParser parser) {
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
        ClassWithAnnotations generatedInstance = new ClassWithAnnotations();
        if (lastByte != '}') {
            parser.byteRollback();
            do {
                parser.nextToken();
                int hash = parser.readStringAsHash();
                parser.nextToken();
                parser.nextToken();
                switch(hash) {
                    case -1409755939: //second
                        generatedInstance.setSecond(deserializerString.fromJson(parser));
                        break;
                    case 1777944894: //third
                        generatedInstance.third = THIRD_DESERIALIZER.fromJson(parser);
                        break;
                    case 1869566211: //deserName
                        generatedInstance.setName(deserializerString.fromJson(parser));
                        break;
                    case 1262358641: //fourth
                        generatedInstance.fourth = deserializerString.fromJson(parser);
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
        builder.registerConverter(ClassWithAnnotations.class, this);
    }

}
