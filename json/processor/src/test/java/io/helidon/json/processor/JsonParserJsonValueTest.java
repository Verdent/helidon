package io.helidon.json.processor;

class JsonParserJsonValueTest extends JsonValueParsingTest {

    @Override
    JsonParser createParser(String template) {
        return JsonParser.create(template);
    }

}
