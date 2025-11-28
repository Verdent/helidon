package io.helidon.json;

class JsonParserSingleValueTest extends SingleValueTest{

    @Override
    JsonParser createParser(String template) {
        return JsonParser.create(template);
    }

}
