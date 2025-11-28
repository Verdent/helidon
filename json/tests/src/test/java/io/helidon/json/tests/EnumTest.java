package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;
import io.helidon.json.JsonException;
import io.helidon.service.registry.Services;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EnumTest {

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);

    @Test
    public void testRootEnumProcessing() {
        String expected = "\"VALUE1\"";
        String json = HELIDON.serialize(TestEnum.VALUE1);
        assertThat(json, is(expected));

        TestEnum testEnum = HELIDON.deserialize(expected, TestEnum.class);
        assertThat(testEnum, is(TestEnum.VALUE1));
    }

    @Test
    public void testEnumInObject() {
        String expected = "{\"enumValue\":\"VALUE2\"}";
        String json = HELIDON.serialize(new RecordWithEnum(TestEnum.VALUE2));
        assertThat(json, is(expected));

        RecordWithEnum recordWithEnum = HELIDON.deserialize(expected, RecordWithEnum.class);
        assertThat(recordWithEnum.enumValue, is(TestEnum.VALUE2));
    }

    @Test
    public void testEnumInObjectAsNull() {
        String json = HELIDON.serialize(new RecordWithEnum(null));
        assertThat(json, is("{}"));

        String expected = "{\"enumValue\":null}";
        RecordWithEnum recordWithEnum = HELIDON.deserialize(expected, RecordWithEnum.class);
        assertThat(recordWithEnum.enumValue, is(nullValue()));
        recordWithEnum = HELIDON.deserialize("{}", RecordWithEnum.class);
        assertThat(recordWithEnum.enumValue, is(nullValue()));
    }

    @Test
    public void testInvalidEnumValue() {
        assertThrows(JsonException.class, () -> HELIDON.deserialize("\"INVALID\"", TestEnum.class));
    }

    enum TestEnum {
        VALUE1,
        VALUE2,
        VALUE3
    }

    @Json.Entity
    record RecordWithEnum(TestEnum enumValue) {
    }

}
