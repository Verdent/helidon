package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class ArrayTest {

    @Test
    public void testOneDimensionPrimitiveArray() {
        int[] expectedArray = {1, 2, 3};
        OneDimensionPrimitiveArray recordWithArray = new OneDimensionPrimitiveArray(expectedArray);
        String serializedJson = JsonBinding.serialize(recordWithArray);
        assertThat(serializedJson, is("{\"intArray\":[1,2,3]}"));

        OneDimensionPrimitiveArray deserialized = JsonBinding.deserialize(serializedJson, OneDimensionPrimitiveArray.class);
        assertThat(deserialized, notNullValue());
        assertThat(deserialized.intArray(), is(expectedArray));
    }

    @Test
    public void testTwoDimensionPrimitiveArray() {
        int[][] expectedArray = {{1, 2, 3}, {4, 5}, {7}};
        TwoDimensionPrimitiveArray recordWithArray = new TwoDimensionPrimitiveArray(expectedArray);
        String serializedJson = JsonBinding.serialize(recordWithArray);
        assertThat(serializedJson, is("{\"intArray\":[[1,2,3],[4,5],[7]]}"));

        TwoDimensionPrimitiveArray deserialized = JsonBinding.deserialize(serializedJson, TwoDimensionPrimitiveArray.class);
        assertThat(deserialized, notNullValue());
        assertThat(deserialized.intArray(), is(expectedArray));
    }

    @Test
    public void testOneDimensionReferenceTypeArray() {
        String[] expectedArray = {"Hi", "Hello"};
        OneDimensionReferenceTypeArray recordWithArray = new OneDimensionReferenceTypeArray(expectedArray);
        String serializedJson = JsonBinding.serialize(recordWithArray);
        assertThat(serializedJson, is("{\"stringArray\":[\"Hi\",\"Hello\"]}"));

        OneDimensionReferenceTypeArray deserialized = JsonBinding.deserialize(serializedJson, OneDimensionReferenceTypeArray.class);
        assertThat(deserialized, notNullValue());
        assertThat(deserialized.stringArray(), is(expectedArray));
    }

    @Test
    public void testTwoDimensionReferenceTypeArray() {
        String[][] expectedArray = {{"Hi", "Hello"}, {"Test", "value", "is here"}};
        TwoDimensionReferenceTypeArray recordWithArray = new TwoDimensionReferenceTypeArray(expectedArray);
        String serializedJson = JsonBinding.serialize(recordWithArray);
        assertThat(serializedJson, is("{\"stringArray\":[[\"Hi\",\"Hello\"],[\"Test\",\"value\",\"is here\"]]}"));

        TwoDimensionReferenceTypeArray deserialized = JsonBinding.deserialize(serializedJson, TwoDimensionReferenceTypeArray.class);
        assertThat(deserialized, notNullValue());
        assertThat(deserialized.stringArray(), is(expectedArray));
    }

    @Json.Entity
    record OneDimensionPrimitiveArray(int[] intArray) {
    }

    @Json.Entity
    record TwoDimensionPrimitiveArray(int[][] intArray) {
    }

    @Json.Entity
    record OneDimensionReferenceTypeArray(String[] stringArray) {
    }

    @Json.Entity
    record TwoDimensionReferenceTypeArray(String[][] stringArray) {
    }

}
