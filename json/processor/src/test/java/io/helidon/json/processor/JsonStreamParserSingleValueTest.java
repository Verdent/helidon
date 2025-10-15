package io.helidon.json.processor;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class JsonStreamParserSingleValueTest extends SingleValueTest{

    @Override
    JsonParser createParser(String template) {
        ByteArrayInputStream stream = new ByteArrayInputStream(template.getBytes(StandardCharsets.UTF_8));
        return JsonParser.create(stream);
    }

}
