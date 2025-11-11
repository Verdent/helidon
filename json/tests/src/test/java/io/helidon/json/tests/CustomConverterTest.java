package io.helidon.json.tests;

import io.helidon.common.GenericType;
import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class CustomConverterTest {

    private static final JsonBinding HELIDON = JsonBinding.create();

    @Test
    public void testCustomConverterOverTheBuilder() {
        JsonBinding jsonBinding = JsonBinding.builder()
                .addConverter(new StringConverter())
                .build();

        String original = "string value";
        String expected = "\"string value_custom_converter\"";
        String expectedDeserialized = "string value" + "_deserialized";
        assertThat(jsonBinding.serialize(original), is(expected));
        assertThat(jsonBinding.deserialize(expected, String.class), is(expectedDeserialized));
    }

    @Test
    public void testCustomDeserializerOverTheBuilder() {
        JsonBinding jsonBinding = JsonBinding.builder()
                .addDeserializer(new StringConverter())
                .build();

        String original = "string value";
        String expected = "\"string value\"";
        String expectedDeserialized = "string value" + "_deserialized";
        assertThat(jsonBinding.serialize(original), is(expected));
        assertThat(jsonBinding.deserialize(expected, String.class), is(expectedDeserialized));
    }

    @Test
    public void testCustomSerializerOverTheBuilder() {
        JsonBinding jsonBinding = JsonBinding.builder()
                .addSerializer(new StringConverter())
                .build();

        String original = "string value";
        String expected = "\"string value_custom_converter\"";
        String expectedDeserialized = "string value_custom_converter";
        assertThat(jsonBinding.serialize(original), is(expected));
        assertThat(jsonBinding.deserialize(expected, String.class), is(expectedDeserialized));
    }
    
    @Test
    public void testCustomSerializerOnTheField() {
        CustomFieldSerializer instance = new CustomFieldSerializer("without serializer", "with serializer");
        String expected = "{\"fieldWithoutSerializer\":\"without serializer\","
                + "\"fieldWithSerializer\":\"with serializer_custom_converter\"}";
        CustomFieldSerializer expectedDeserialized = new CustomFieldSerializer("without serializer",
                                                                               "with serializer_custom_converter");
        assertThat(HELIDON.serialize(instance), is(expected));
        assertThat(HELIDON.deserialize(expected, CustomFieldSerializer.class), is(expectedDeserialized));
    }

    @Test
    public void testCustomDeserializerOnTheField() {
        CustomFieldDeserializer instance = new CustomFieldDeserializer("without deserializer", "with deserializer");
        String expected = "{\"fieldWithoutDeserializer\":\"without deserializer\","
                + "\"fieldWithDeserializer\":\"with deserializer\"}";
        CustomFieldDeserializer expectedDeserialized = new CustomFieldDeserializer("without deserializer",
                                                                                   "with deserializer_deserialized");
        assertThat(HELIDON.serialize(instance), is(expected));
        assertThat(HELIDON.deserialize(expected, CustomFieldDeserializer.class), is(expectedDeserialized));
    }

    static class StringConverter implements JsonConverter<String> {
        @Override
        public String deserialize(JsonParser parser) {
            String string = parser.readString();
            int index = string.indexOf("_");
            if (index == -1) {
                index = string.length();
            }
            return string.substring(0, index) + "_deserialized";
        }

        @Override
        public GenericType<String> type() {
            return GenericType.create(String.class);
        }

        @Override
        public void serialize(Generator generator, String instance, boolean writeNulls) {
            generator.write(instance + "_custom_converter");
        }
    }

    @Json.Entity
    record CustomFieldSerializer(String fieldWithoutSerializer,
                                 @Json.Serializer(StringConverter.class) String fieldWithSerializer) {
    }

    @Json.Entity
    record CustomFieldDeserializer(String fieldWithoutDeserializer,
                                   @Json.Deserializer(StringConverter.class) String fieldWithDeserializer) {
    }

}
