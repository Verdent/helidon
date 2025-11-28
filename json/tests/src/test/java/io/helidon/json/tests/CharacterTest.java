package io.helidon.json.tests;

import io.helidon.json.binding.JsonBinding;
import io.helidon.service.registry.Services;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class CharacterTest {

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);

    @Test
    public void testAsciiChar() {
        String expected = "\"a\"";
        char c = 'a';
        String jsonValue = HELIDON.serialize(c);
        assertThat(jsonValue, is(expected));

        char deserialized = HELIDON.deserialize(jsonValue, char.class);
        assertThat(deserialized, is(c));
    }

    @Test
    public void testUTF8Char() {
        String expected = "\"ř\"";
        char c = 'ř';
        String jsonValue = HELIDON.serialize(c);
        assertThat(jsonValue, is(expected));

        char deserialized = HELIDON.deserialize(jsonValue, char.class);
        assertThat(deserialized, is(c));
    }

    @Test
    public void testUnicodeChar() {
        String jsonValue = "\"\\u0041\"";

        char deserialized = HELIDON.deserialize(jsonValue, char.class);
        assertThat(deserialized, is('A'));
    }
}
