package io.helidon.json.tests;

import io.helidon.json.JsonException;
import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;
import io.helidon.service.registry.Services;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class ExceptionReportingTest {

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);

    @Test
    public void unexpectedStringEnd() {
//        assertThrows(JsonException.class, () -> HELIDON.deserialize("{\"value", TestData.class));
//        assertThrows(JsonException.class, () -> HELIDON.deserialize("{\"value\":\"something}", TestData.class));
        HELIDON.deserialize("{\"value:123}", TestData.class);
    }

    @Test
    public void unexpectedJsonValue() {
        assertThrows(JsonException.class, () -> HELIDON.deserialize("{\"value\":none}", TestData.class));
        //        HELIDON.deserialize("{\"value:123}", TestData.class);
    }

    @Test
    public void testTooLargeNumbers() {
        String testValue = "1".repeat(20);
        assertThrows(JsonException.class, () -> HELIDON.deserialize(testValue, byte.class));
        assertThrows(JsonException.class, () -> HELIDON.deserialize(testValue, short.class));
        assertThrows(JsonException.class, () -> HELIDON.deserialize(testValue, int.class));
        assertThrows(JsonException.class, () -> HELIDON.deserialize(testValue, long.class));
        assertThrows(JsonException.class, () -> HELIDON.deserialize(testValue, float.class));
        assertThrows(JsonException.class, () -> HELIDON.deserialize(testValue, double.class));
    }

    @Json.Entity
    record TestData(String value) {
    }

}
