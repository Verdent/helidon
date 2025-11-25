package io.helidon.json.processor;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

class JsonStreamParserJsonValueTest extends JsonValueParsingTest {

    @Override
    JsonParser createParser(String template) {
        ByteArrayInputStream stream = new ByteArrayInputStream(template.getBytes(StandardCharsets.UTF_8));
        return JsonParser.create(stream, 15);
    }

}
