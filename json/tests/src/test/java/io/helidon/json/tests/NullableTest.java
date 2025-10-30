package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class NullableTest {
    
    private static final JsonBinding HELIDON = JsonBinding.create();

    @Test
    public void testJsonNullableOnRecord() {
        JsonNullableOnRecord instance = new JsonNullableOnRecord(null, null);
        assertEquals("{\"someField\":null,\"someField2\":null}", HELIDON.serialize(instance));
    }

    @Test
    public void testJsonNullableOnRecordComponent() {
        JsonNullableOnRecordComponent instance = new JsonNullableOnRecordComponent(null, null);
        assertEquals("{\"someField\":null}", HELIDON.serialize(instance));
    }

    @Test
    public void testJsonNullableOverrideOnField() {
        NullableOverrideOnField instance = new NullableOverrideOnField();
        assertEquals("{\"field2\":null}", HELIDON.serialize(instance));
    }

    @Test
    public void testJsonNullableOverrideOnMethod() {
        NullableOverrideOnMethod instance = new NullableOverrideOnMethod();
        assertEquals("{\"field2\":null}", HELIDON.serialize(instance));
    }

    @Test
    public void testJsonNullableFromParent() {
        NullableChild instance = new NullableChild();
        assertEquals("{\"field\":null}", HELIDON.serialize(instance));
    }
    @Test
    public void testJsonNullableFromParentOverride() {
        NonNullableChild instance = new NonNullableChild();
        assertEquals("{}", HELIDON.serialize(instance));
    }

    @Json.Entity
    @Json.Nullable
    record JsonNullableOnRecord(String someField, String someField2) {
    }

    @Json.Entity
    record JsonNullableOnRecordComponent(@Json.Nullable String someField, String someField2) {
    }

    @Json.Entity
    @Json.Nullable
    static class NullableOverrideOnField {
        @Json.Nullable(false)
        String field = null;
        String field2 = null;
    }

    @Json.Entity(accessorStyle = true)
    @Json.Nullable
    static class NullableOverrideOnMethod {
        String field = null;
        String field2 = null;

        @Json.Nullable(false)
        public String field() {
            return field;
        }
    }

    @Json.Nullable
    static class NullableParent {
    }

    @Json.Entity
    static class NullableChild extends NullableParent {
        String field = null;
    }

    @Json.Entity
    @Json.Nullable(false)
    static class NonNullableChild extends NullableParent {
        String field = null;
    }

}
