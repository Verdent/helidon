package io.helidon.json.processor;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.is;

public class JsonParserImplTest {

    @Test
    public void testParseString() {
        String expected = "Test String value";
        JsonParserImpl parser = new JsonParserImpl("\"" + expected + "\"");
        parser.nextToken();

        assertThat(parser.readString(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testParseInt() {
        String expected = "1234";
        JsonParserImpl parser = new JsonParserImpl(expected);
        parser.nextToken();

        assertThat(parser.readAsInt(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }
}
