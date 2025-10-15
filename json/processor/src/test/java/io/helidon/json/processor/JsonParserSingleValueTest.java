package io.helidon.json.processor;

class JsonParserSingleValueTest extends SingleValueTest{

    @Override
    JsonParser createParser(String template) {
        return JsonParser.create(template);
    }

}
