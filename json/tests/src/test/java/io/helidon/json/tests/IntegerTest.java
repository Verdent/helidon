package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

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

    @Json.Entity
    record IntegerModel(Integer object, int primitive) {

    }

}
