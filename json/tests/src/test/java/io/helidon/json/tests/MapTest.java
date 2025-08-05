package io.helidon.json.tests;

import java.util.HashMap;
import java.util.Map;

import io.helidon.common.GenericType;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

public class MapTest {

    @Test
    public void testMapSerialization() {
        Map<String, String> map = new HashMap<>();
        map.put("key1", "value1");
        map.put("key2", "value2");
        map.put("key3", "value3");

        String expected = "{\"key1\":\"value1\",\"key2\":\"value2\",\"key3\":\"value3\"}";
        assertThat(JsonBinding.serialize(map), is(expected));
    }

    @Test
    public void testMapDeserialization() {
        String json = "{\"key1\":\"value1\",\"key2\":\"value2\",\"key3\":\"value3\"}";

        GenericType<Map<String, String>> type = new GenericType<>() { };
        Map<String, String> map = JsonBinding.deserialize(json, type);

        assertThat(map, notNullValue());
        assertThat(map, instanceOf(HashMap.class));
        assertThat(map.size(), is(3));
        assertThat(map, hasEntry("key1", "value1"));
        assertThat(map, hasEntry("key2", "value2"));
        assertThat(map, hasEntry("key3", "value3"));
    }

    @Test
    public void testMapSerializationWithNulls() {
        Map<String, String> map = new HashMap<>();
        map.put("key1", null);
        map.put("key2", null);
        map.put("key3", null);

        String expected = "{\"key1\":null,\"key2\":null,\"key3\":null}";
        assertThat(JsonBinding.serialize(map), is(expected));
    }

    @Test
    public void testMapDeserializationWithNulls() {
        String json = "{\"key1\":null,\"key2\":null,\"key3\":null}";

        GenericType<Map<String, String>> type = new GenericType<>() { };
        Map<String, String> map = JsonBinding.deserialize(json, type);

        assertThat(map, notNullValue());
        assertThat(map, instanceOf(HashMap.class));
        assertThat(map.size(), is(3));
        assertThat(map, hasEntry("key1", null));
        assertThat(map, hasEntry("key2", null));
        assertThat(map, hasEntry("key3", null));
    }

}
