package io.helidon.json.tests;

import io.helidon.json.binding.JsonBinding;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class CustomConverterTest {

    @Test
    public void testCustomConverterOverBuilder() {
        JsonBinding jsonBinding = JsonBinding.builder()
                .addConverter(new StringConverter())
                .build();

        String original = "string value";
        String expected = "\"string value_custom_converter\"";
        String expectedDeserialized = "string value" + "_deserialized";
        assertThat(jsonBinding.toJson(original), is(expected));
        assertThat(jsonBinding.fromJson(expected, String.class), is(expectedDeserialized));
    }

    @Test
    public void testCustomDeserializerOverBuilder() {
        JsonBinding jsonBinding = JsonBinding.builder()
                .addDeserializer(new StringConverter())
                .build();

        String original = "string value";
        String expected = "\"string value\"";
        String expectedDeserialized = "string value" + "_deserialized";
        assertThat(jsonBinding.toJson(original), is(expected));
        assertThat(jsonBinding.fromJson(expected, String.class), is(expectedDeserialized));
    }

    @Test
    public void testCustomSerializerOverBuilder() {
        JsonBinding jsonBinding = JsonBinding.builder()
                .addSerializer(new StringConverter())
                .build();

        String original = "string value";
        String expected = "\"string value_custom_converter\"";
        String expectedDeserialized = "string value_custom_converter";
        assertThat(jsonBinding.toJson(original), is(expected));
        assertThat(jsonBinding.fromJson(expected, String.class), is(expectedDeserialized));
    }

    static class StringConverter implements TypedJsonConverter<String> {
        @Override
        public String fromJsonValue(JsonParser parser) {
            String string = parser.readString();
            int index = string.indexOf("_");
            if (index == -1) {
                index = string.length();
            }
            return string.substring(0, index) + "_deserialized";
        }

        @Override
        public void toJson(Generator generator, String instance, boolean writeNulls) {
            generator.writeQuoted(instance + "_custom_converter");
        }
    }

}
