package io.helidon.json.processor;

import java.math.BigDecimal;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

abstract class JsonValueParsingTest {

    @Test
    public void testJsonStringValueParsing() {
        String json = "\"stringValue\"";
        JsonParser parser = createParser(json);
        JsonValue jsonValue = parser.readJsonValue();

        assertThat(jsonValue.type(), is(JsonValueType.STRING));
        assertThat(jsonValue.asString().value(), is("stringValue"));
    }

    @Test
    public void testJsonNumberValueParsing() {
        String json = "123";
        JsonParser parser = createParser(json);
        JsonValue jsonValue = parser.readJsonValue();

        assertThat(jsonValue.type(), is(JsonValueType.NUMBER));
        assertThat(jsonValue.asNumber().doubleValue(), is(123.0));

        json = "123.456";
        parser = createParser(json);
        jsonValue = parser.readJsonValue();

        assertThat(jsonValue.type(), is(JsonValueType.NUMBER));
        assertThat(jsonValue.asNumber().doubleValue(), is(123.456));
    }

    @Test
    public void testJsonObjectParsing() {
        String expected = "value".repeat(6);
        String json = "{\"test\":\"" + expected + "\"}";
        JsonParser parser = JsonParser.create(json);
        JsonValue jsonValue = parser.readJsonValue();

        assertThat(jsonValue.type(), is(JsonValueType.OBJECT));
        assertThat(jsonValue.asObject().containsKey("test"), is(true));
        assertThat(jsonValue.asObject().stringValue("test").orElseThrow(), is(expected));
        assertThat(jsonValue.asObject().containsKey("missing"), is(false));
    }

    @Test
    public void testJsonObjectWithNumberParsing() {
        String expected = "123".repeat(3);
        String json = "{\"test\":" + expected + "}";
        JsonParser parser = JsonParser.create(json);
        JsonValue jsonValue = parser.readJsonValue();

        assertThat(jsonValue.type(), is(JsonValueType.OBJECT));
        assertThat(jsonValue.asObject().containsKey("test"), is(true));
        assertThat(jsonValue.asObject().numberValue("test").orElseThrow(), is(new BigDecimal(expected)));
        assertThat(jsonValue.asObject().containsKey("missing"), is(false));
    }

    abstract JsonParser createParser(String template);

}
