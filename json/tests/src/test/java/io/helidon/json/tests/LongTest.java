package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;
import io.helidon.service.registry.Services;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class LongTest {

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);

    @Test
    public void testLongSerialization() {
        LongModel model = new LongModel(123L, 456);

        String expected = "{\"object\":123,\"primitive\":456}";
        assertThat(HELIDON.serialize(model), is(expected));
    }

    @Test
    public void testLongDeserializationFromLongAsStringValue() {
        LongModel longModel = HELIDON.deserialize("{\"object\":\"123\",\"primitive\":\"456\"}", LongModel.class);
        assertThat(longModel.object, is(123L));
        assertThat(longModel.primitive, is(456L));
    }

    @Test
    public void testLongDeserializationFromLongRawValue() {
        LongModel longModel = HELIDON.deserialize("{\"object\":123,\"primitive\":456}", LongModel.class);
        assertThat(longModel.object, is(123L));
        assertThat(longModel.primitive, is(456L));
    }

    @Test
    public void testRawLongs() {
        Long value = HELIDON.deserialize("123", Long.class);
        assertThat(value, is(123L));
        value = HELIDON.deserialize("123", long.class);
        assertThat(value, is(123L));
        value = HELIDON.deserialize("\"123\"", Long.class);
        assertThat(value, is(123L));
        value = HELIDON.deserialize("\"123\"", long.class);
        assertThat(value, is(123L));
        value = HELIDON.deserialize("null", Long.class);
        assertThat(value, is(nullValue()));
        value = HELIDON.deserialize("null", long.class);
        assertThat(value, is(0L));

        String serialized = HELIDON.serialize(123L);
        assertThat(serialized, is("123"));
        serialized = HELIDON.serialize(Long.valueOf(123L));
        assertThat(serialized, is("123"));
    }

    @Json.Entity
    record LongModel(Long object, long primitive) {

    }

}
