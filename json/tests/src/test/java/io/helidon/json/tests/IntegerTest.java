package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class IntegerTest {

    @Test
    public void testIntegerSerialization() {
        IntegerModel model = new IntegerModel(123, 456);

        String expected = "{\"object\":123,\"primitive\":456}";
        assertThat(JsonBinding.serialize(model), is(expected));
    }

    @Test
    public void testIntegerDeserializationFromIntegerAsStringValue() {
        IntegerModel integerModel = JsonBinding.deserialize("{\"object\":\"123\",\"primitive\":\"456\"}", IntegerModel.class);
        assertThat(integerModel.object, is(123));
        assertThat(integerModel.primitive, is(456));
    }

    @Test
    public void testIntegerDeserializationFromIntegerRawValue() {
        IntegerModel integerModel = JsonBinding.deserialize("{\"object\":123,\"primitive\":456}", IntegerModel.class);
        assertThat(integerModel.object, is(123));
        assertThat(integerModel.primitive, is(456));
    }

    @Test
    public void testRawIntegers() {
        Integer value = JsonBinding.deserialize("123", Integer.class);
        assertThat(value, is(123));
        value = JsonBinding.deserialize("123", int.class);
        assertThat(value, is(123));
        value = JsonBinding.deserialize("\"123\"", Integer.class);
        assertThat(value, is(123));
        value = JsonBinding.deserialize("\"123\"", int.class);
        assertThat(value, is(123));
        value = JsonBinding.deserialize("null", Integer.class);
        assertThat(value, is(nullValue()));
        value = JsonBinding.deserialize("null", int.class);
        assertThat(value, is(0));

        String serialized = JsonBinding.serialize(123);
        assertThat(serialized, is("123"));
        serialized = JsonBinding.serialize(Integer.valueOf(123));
        assertThat(serialized, is("123"));
    }

    @Json.Entity
    record IntegerModel(Integer object, int primitive) {

    }

}
