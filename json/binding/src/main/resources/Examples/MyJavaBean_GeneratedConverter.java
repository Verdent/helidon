package org.example;

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

public class MyJavaBean_GeneratedConverter implements JsonConverter<MyJavaBean>, JsonComponentProvider, Configurable {

    private JsonDeserializer<Integer> deserializerInt = null;
    private JsonDeserializer<String> deserializerString = null;
    private JsonDeserializer<ClassWithGenerics<Integer>> deserializerWithGenerics = null;
    private JsonDeserializer<OtherBean> deserializerOtherBean = null;
    private JsonSerializer<Integer> serializerInt = null;
    private JsonSerializer<String> serializerString = null;
    private JsonSerializer<ClassWithGenerics<Integer>> serializerWithGenerics = null;
    private JsonSerializer<OtherBean> serializerOtherBean = null;

    @Override
    public void toJson(Generator generator, MyJavaBean instance) {
        if (instance == null) {
            generator.writeNull();
            return;
        }
        generator.writeObjectStart();
        generator.writeKey("fieldOne");
        serializerString.toJson(generator, instance.getFieldOne());
        generator.writeComma();
        generator.writeKey("fieldTwo");
        serializerInt.toJson(generator, instance.getFieldTwo());
        generator.writeComma();
        generator.writeKey("fieldThree");
        serializerString.toJson(generator, instance.getFieldThree());
        generator.writeComma();
        generator.writeKey("fieldFour");
        serializerString.toJson(generator, instance.getFieldFour());
        generator.writeComma();
        generator.writeKey("fieldFive");
        serializerString.toJson(generator, instance.getFieldFive());
        generator.writeComma();
        generator.writeKey("otherBean");
        serializerOtherBean.toJson(generator, instance.getOtherBean());
        generator.writeComma();
        generator.writeKey("withGenerics");
        serializerWithGenerics.toJson(generator, instance.getWithGenerics());
        generator.writeObjectEnd();
    }

    @Override
    public MyJavaBean fromJson(JsonObject jsonObject) {
        return null;
    }

    @Override
    public MyJavaBean fromJson(JsonParser parser) {
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
        MyJavaBean generatedInstance = new MyJavaBean();
        if (lastByte != '}') {
            parser.byteRollback();
            do {
                parser.nextToken();
                int hash = parser.readStringAsHash();
                parser.nextToken();
                parser.nextToken();
                switch(hash) {
                    case 1070767187: //fieldFour
                        generatedInstance.setFieldFour(deserializerString.fromJson(parser));
                        break;
                    case 287402981: //fieldThree
                        generatedInstance.setFieldThree(deserializerString.fromJson(parser));
                        break;
                    case 1701905495: //fieldFive
                        generatedInstance.setFieldFive(deserializerString.fromJson(parser));
                        break;
                    case -170780731: //fieldOne
                        generatedInstance.setFieldOne(deserializerString.fromJson(parser));
                        break;
                    case -1386242761: //otherBean
                        generatedInstance.setOtherBean(deserializerOtherBean.fromJson(parser));
                        break;
                    case -896288081: //fieldTwo
                        generatedInstance.setFieldTwo(deserializerInt.fromJson(parser));
                        break;
                    case 787616895: //withGenerics
                        generatedInstance.setWithGenerics(deserializerWithGenerics.fromJson(parser));
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
        serializerInt = runtimeJson.getSerializer(int.class);
        serializerOtherBean = runtimeJson.getSerializer(OtherBean.class);
        ParamTypeHelper<ClassWithGenerics<Integer>> serHelperWithGenerics = new ParamTypeHelper<>() {};
        serializerWithGenerics = runtimeJson.getSerializer(serHelperWithGenerics.getType());
        deserializerString = runtimeJson.getDeserializer(String.class);
        deserializerOtherBean = runtimeJson.getDeserializer(OtherBean.class);
        deserializerInt = runtimeJson.getDeserializer(int.class);
        ParamTypeHelper<ClassWithGenerics<Integer>> desHelperWithGenerics = new ParamTypeHelper<>() {};
        deserializerWithGenerics = runtimeJson.getDeserializer(desHelperWithGenerics.getType());
    }

    @Override
    public void register(RuntimeJson.Builder builder) {
        builder.registerConverter(MyJavaBean.class, this);
    }

}
