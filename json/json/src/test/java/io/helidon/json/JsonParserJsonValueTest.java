package io.helidon.json;

class JsonParserJsonValueTest extends JsonValueParsingTest {

    @Override
    JsonParser createParser(String template) {
        return JsonParser.create(template);
    }

}
