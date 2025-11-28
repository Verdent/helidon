package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;
import io.helidon.json.JsonException;
import io.helidon.service.registry.Services;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class FailOnUnknownTest {

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);

    @Test
    public void testFailOnUnknownDisabled() {
        // Without @FailOnUnknown, unknown properties should be ignored
        String json = "{\"knownField\":\"value\",\"unknownField\":\"ignored\"}";
        NoFailOnUnknown entity = HELIDON.deserialize(json, NoFailOnUnknown.class);
        assertThat(entity.knownField, is("value"));
    }

    @Test
    public void testFailOnUnknownEnabled() {
        // With @FailOnUnknown, unknown properties should cause failure
        String json = "{\"knownField\":\"value\",\"unknownField\":\"should_fail\"}";
        assertThrows(JsonException.class, () -> HELIDON.deserialize(json, FailOnUnknownEnabled.class));
    }

    @Test
    public void testFailOnUnknownEnabledKnownOnly() {
        // With @FailOnUnknown, but only known properties, should succeed
        String json = "{\"knownField\":\"value\"}";
        FailOnUnknownEnabled entity = HELIDON.deserialize(json, FailOnUnknownEnabled.class);
        assertThat(entity.knownField, is("value"));
    }

    @Json.Entity
    static class NoFailOnUnknown {
        public String knownField;
    }

    @Json.Entity
    @Json.FailOnUnknown
    static class FailOnUnknownEnabled {
        public String knownField;
    }
}
