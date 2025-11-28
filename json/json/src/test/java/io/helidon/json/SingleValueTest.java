package io.helidon.json;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

abstract class SingleValueTest {

    @Test
    public void testParseString() {
        String expected = "Test String value";
        JsonParser parser = createParser("\"" + expected + "\"");

        assertThat(parser.readString(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testParseByte() {
        byte expected = 125;
        String template = "125";
        JsonParser parser = createParser(template);

        assertThat(parser.readAsByte(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testParseShort() {
        short expected = 12345;
        String template = "12345";
        JsonParser parser = createParser(template);

        assertThat(parser.readAsShort(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testParseInt() {
        int expected = 1234;
        String template = "1234";
        JsonParser parser = createParser(template);

        assertThat(parser.readAsInt(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testParseLong() {
        long expected = 123456789123456L;
        String template = "123456789123456";
        JsonParser parser = createParser(template);

        assertThat(parser.readAsLong(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testParseDouble() {
        double expected = 123.456e10;
        String template = "123.456e10";
        JsonParser parser = createParser(template);

        assertThat(parser.readAsDouble(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testParseFloat() {
        float expected = 123.456e10F;
        String template = "123.456e10";
        JsonParser parser = createParser(template);

        assertThat(parser.readAsFloat(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testParseBoolean() {
        boolean expected = true;
        String template = "true";
        JsonParser parser = createParser(template);

        assertThat(parser.readAsBoolean(), is(expected));
        assertThat(parser.hasNext(), is(false));

        expected = false;
        template = "false";
        parser = createParser(template);

        assertThat(parser.readAsBoolean(), is(expected));
        assertThat(parser.hasNext(), is(false));
    }

    @Test
    public void testParseNull() {
        String template = "null";
        JsonParser parser = createParser(template);

        assertThat(parser.checkNull(), is(true));
        assertThat(parser.hasNext(), is(false));
    }

    abstract JsonParser createParser(String template);

}
