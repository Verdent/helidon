package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class BasicTest {

    private static final String EXPECTED_VALUE = "{\"value\":\"abc\"}";
    private static final JsonBinding HELIDON = JsonBinding.create();

    @Test
    public void testSimpleSerialize() {
        StringWrapper wrapper = new StringWrapper();
        wrapper.setValue("abc");
        String val = HELIDON.serialize(wrapper);
        assertThat(val, is(EXPECTED_VALUE));
    }

    @Test
    public void testSimpleDeserializer() {
        StringWrapper stringWrapper = HELIDON.deserialize(EXPECTED_VALUE, StringWrapper.class);
        assertEquals("abc", stringWrapper.value);
    }

    @Json.Entity
    static class StringWrapper {

        private String value;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

}
