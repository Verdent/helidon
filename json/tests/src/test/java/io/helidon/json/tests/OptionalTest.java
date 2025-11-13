package io.helidon.json.tests;

import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

import io.helidon.common.GenericType;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class OptionalTest {

    private static final JsonBinding JSON_BINDING = JsonBinding.create();

    @Test
    void testEmptyOptional() {
        Optional<Object> optional = Optional.empty();
        String expected = "null";
        String serialized = JSON_BINDING.serialize(optional);

        assertThat(serialized, is(expected));

        Optional<Object> deserialized = JSON_BINDING.deserialize(expected, new GenericType<>(){});
        assertThat(deserialized, is(optional));
    }

    @Test
    void testOptional() {
        Optional<String> optional = Optional.of("Hello");
        String expected = "\"Hello\"";

        GenericType<Optional<String>> genericType = new GenericType<>() { };
        String serialized = JSON_BINDING.serialize(optional, genericType);

        assertThat(serialized, is(expected));

        Optional<String> deserialized = JSON_BINDING.deserialize(expected, genericType);
        assertThat(deserialized, is(optional));
    }

    @Test
    void testEmptyOptionalInt() {
        OptionalInt optional = OptionalInt.empty();
        String expected = "null";
        String serialized = JSON_BINDING.serialize(optional);

        assertThat(serialized, is(expected));

        OptionalInt deserialized = JSON_BINDING.deserialize(expected, OptionalInt.class);
        assertThat(deserialized, is(optional));
    }

    @Test
    void testOptionalInt() {
        OptionalInt optional = OptionalInt.of(123);
        String expected = "123";

        String serialized = JSON_BINDING.serialize(optional);

        assertThat(serialized, is(expected));

        OptionalInt deserialized = JSON_BINDING.deserialize(expected, OptionalInt.class);
        assertThat(deserialized, is(optional));
    }

    @Test
    void testEmptyOptionalLong() {
        OptionalLong optional = OptionalLong.empty();
        String expected = "null";
        String serialized = JSON_BINDING.serialize(optional);

        assertThat(serialized, is(expected));

        OptionalLong deserialized = JSON_BINDING.deserialize(expected, OptionalLong.class);
        assertThat(deserialized, is(optional));
    }

    @Test
    void testOptionalLong() {
        OptionalLong optional = OptionalLong.of(123);
        String expected = "123";

        String serialized = JSON_BINDING.serialize(optional);

        assertThat(serialized, is(expected));

        OptionalLong deserialized = JSON_BINDING.deserialize(expected, OptionalLong.class);
        assertThat(deserialized, is(optional));
    }

    @Test
    void testEmptyOptionalDouble() {
        OptionalDouble optional = OptionalDouble.empty();
        String expected = "null";
        String serialized = JSON_BINDING.serialize(optional);

        assertThat(serialized, is(expected));

        OptionalDouble deserialized = JSON_BINDING.deserialize(expected, OptionalDouble.class);
        assertThat(deserialized, is(optional));
    }

    @Test
    void testOptionalDouble() {
        OptionalDouble optional = OptionalDouble.of(123.456);
        String expected = "123.456";

        String serialized = JSON_BINDING.serialize(optional);

        assertThat(serialized, is(expected));

        OptionalDouble deserialized = JSON_BINDING.deserialize(expected, OptionalDouble.class);
        assertThat(deserialized, is(optional));
    }

}
