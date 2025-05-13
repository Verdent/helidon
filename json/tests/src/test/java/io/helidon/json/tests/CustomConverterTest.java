package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class CustomConverterTest {

    @Test
    public void testCustomConverterOverTheBuilder() {
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
    public void testCustomDeserializerOverTheBuilder() {
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
    public void testCustomSerializerOverTheBuilder() {
        JsonBinding jsonBinding = JsonBinding.builder()
                .addSerializer(new StringConverter())
                .build();

        String original = "string value";
        String expected = "\"string value_custom_converter\"";
        String expectedDeserialized = "string value_custom_converter";
        assertThat(jsonBinding.toJson(original), is(expected));
        assertThat(jsonBinding.fromJson(expected, String.class), is(expectedDeserialized));
    }
    
    @Test
    public void testCustomSerializerOnTheField() {
        CustomFieldSerializer instance = new CustomFieldSerializer("without serializer", "with serializer");
        String expected = "{\"fieldWithoutSerializer\":\"without serializer\","
                + "\"fieldWithSerializer\":\"with serializer_custom_converter\"}";
        CustomFieldSerializer expectedDeserialized = new CustomFieldSerializer("without serializer",
                                                                               "with serializer_custom_converter");
        assertThat(JsonBinding.serialize(instance), is(expected));
        assertThat(JsonBinding.deserialize(expected, CustomFieldSerializer.class), is(expectedDeserialized));
    }

    @Test
    public void testCustomDeserializerOnTheField() {
        CustomFieldDeserializer instance = new CustomFieldDeserializer("without deserializer", "with deserializer");
        String expected = "{\"fieldWithoutDeserializer\":\"without deserializer\","
                + "\"fieldWithDeserializer\":\"with deserializer\"}";
        CustomFieldDeserializer expectedDeserialized = new CustomFieldDeserializer("without deserializer",
                                                                                   "with deserializer_deserialized");
        assertThat(JsonBinding.serialize(instance), is(expected));
        assertThat(JsonBinding.deserialize(expected, CustomFieldDeserializer.class), is(expectedDeserialized));
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

    @Json.Entity
    record CustomFieldSerializer(String fieldWithoutSerializer,
                                 @Json.Serializer(StringConverter.class) String fieldWithSerializer) {
    }

    @Json.Entity
    record CustomFieldDeserializer(String fieldWithoutDeserializer,
                                   @Json.Deserializer(StringConverter.class) String fieldWithDeserializer) {
    }

}
