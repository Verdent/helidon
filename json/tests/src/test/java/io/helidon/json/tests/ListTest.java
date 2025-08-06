package io.helidon.json.tests;

import java.util.ArrayList;
import java.util.List;

import io.helidon.common.GenericType;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class ListTest {

    @Test
    public void testListSerialization() {
        List<String> list = List.of("a", "b", "c");

        String expected = "[\"a\",\"b\",\"c\"]";

        String json = JsonBinding.serialize(list);
        assertThat(json, is(expected));
    }

    @Test
    public void testListDeserialization() {
        List<String> list = List.of("a", "b", "c");

        String json = "[\"a\",\"b\",\"c\"]";

        GenericType<List<String>> type = new GenericType<>() { };
        List<String> deserialized = JsonBinding.deserialize(json, type);
        assertThat(deserialized, is(list));
    }

}
