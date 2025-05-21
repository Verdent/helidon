package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class LongTest {

    @Test
    public void testLongSerialization() {
        LongModel model = new LongModel(123L, 456);

        String expected = "{\"object\":123,\"primitive\":456}";
        assertThat(JsonBinding.serialize(model), is(expected));
    }

    @Test
    public void testLongDeserializationFromLongAsStringValue() {
        LongModel longModel = JsonBinding.deserialize("{\"object\":\"123\",\"primitive\":\"456\"}", LongModel.class);
        assertThat(longModel.object, is(123L));
        assertThat(longModel.primitive, is(456L));
    }

    @Test
    public void testLongDeserializationFromLongRawValue() {
        LongModel longModel = JsonBinding.deserialize("{\"object\":123,\"primitive\":456}", LongModel.class);
        assertThat(longModel.object, is(123L));
        assertThat(longModel.primitive, is(456L));
    }

    @Test
    public void testRawLongs() {
        Long value = JsonBinding.deserialize("123", Long.class);
        assertThat(value, is(123L));
        value = JsonBinding.deserialize("123", long.class);
        assertThat(value, is(123L));
        value = JsonBinding.deserialize("\"123\"", Long.class);
        assertThat(value, is(123L));
        value = JsonBinding.deserialize("\"123\"", long.class);
        assertThat(value, is(123L));
        value = JsonBinding.deserialize("null", Long.class);
        assertThat(value, is(nullValue()));
        value = JsonBinding.deserialize("null", long.class);
        assertThat(value, is(0L));

        String serialized = JsonBinding.serialize(123L);
        assertThat(serialized, is("123"));
        serialized = JsonBinding.serialize(Long.valueOf(123L));
        assertThat(serialized, is("123"));
    }

    @Json.Entity
    record LongModel(Long object, long primitive) {

    }

}
