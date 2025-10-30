package io.helidon.json.processor;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class JsonValueParsingTest {

    @Test
    public void testJsonStringValueParsing() {
        String json = "\"stringValue\"";
        JsonParser parser = JsonParser.create(json);
        JsonValue jsonValue = parser.readJsonValue();

        assertThat(jsonValue.type(), is(JsonValueType.STRING));
        assertThat(jsonValue.asString().value(), is("stringValue"));
    }

    @Test
    public void testJsonNumberValueParsing() {
        String json = "123";
        JsonParser parser = JsonParser.create(json);
        JsonValue jsonValue = parser.readJsonValue();

        assertThat(jsonValue.type(), is(JsonValueType.NUMBER));
        assertThat(jsonValue.asNumber().doubleValue(), is(123.0));

        json = "123.456";
        parser = JsonParser.create(json);
        jsonValue = parser.readJsonValue();

        assertThat(jsonValue.type(), is(JsonValueType.NUMBER));
        assertThat(jsonValue.asNumber().doubleValue(), is(123.456));
    }

    @Test
    public void testJsonObjectParsing() {
        String json = """
                {
                    "test" : "value"
                }
                """;
        JsonParser parser = JsonParser.create(json);
        JsonValue jsonValue = parser.readJsonValue();

        assertThat(jsonValue.type(), is(JsonValueType.OBJECT));
        assertThat(jsonValue.asObject().containsKey("test"), is(true));
        assertThat(jsonValue.asObject().containsKey("missing"), is(false));
    }



}
