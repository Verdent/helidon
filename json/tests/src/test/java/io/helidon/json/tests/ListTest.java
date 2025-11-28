package io.helidon.json.tests;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import io.helidon.common.GenericType;
import io.helidon.json.binding.JsonBinding;
import io.helidon.service.registry.Services;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

public class ListTest {

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);

    @Test
    public void testListSerialization() {
        List<String> list = List.of("a", "b", "c");

        String expected = "[\"a\",\"b\",\"c\"]";

        String json = HELIDON.serialize(list);
        assertThat(json, is(expected));
    }

    @Test
    public void testListDeserialization() {
        List<String> list = List.of("a", "b", "c");

        String json = "[\"a\",\"b\",\"c\"]";

        GenericType<List<String>> type = new GenericType<>() { };
        List<String> deserialized = HELIDON.deserialize(json, type);
        assertThat(deserialized, is(list));
    }

    @Test
    public void testListTypeDeserialization() {
        List<String> list = List.of("a", "b", "c");

        String json = "[\"a\",\"b\",\"c\"]";

        GenericType<List<String>> listType = new GenericType<>() { };
        List<String> deserialized = HELIDON.deserialize(json, listType);
        assertThat(deserialized, is(list));
        assertThat(deserialized, instanceOf(ArrayList.class));

        GenericType<ArrayList<String>> arrayListType = new GenericType<>() { };
        deserialized = HELIDON.deserialize(json, arrayListType);
        assertThat(deserialized, is(list));
        assertThat(deserialized, instanceOf(ArrayList.class));

        GenericType<LinkedList<String>> linkedListType = new GenericType<>() { };
        deserialized = HELIDON.deserialize(json, linkedListType);
        assertThat(deserialized, is(list));
        assertThat(deserialized, instanceOf(LinkedList.class));
    }

}
