package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

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

    @Json.Entity
    record LongModel(Long object, long primitive) {

    }

}
