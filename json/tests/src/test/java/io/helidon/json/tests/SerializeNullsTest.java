package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SerializeNullsTest {
    
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
    @Json.SerializeNulls
    record JsonNullableOnRecord(String someField, String someField2) {
    }

    @Json.Entity
    record JsonNullableOnRecordComponent(@Json.SerializeNulls String someField, String someField2) {
    }

    @Json.Entity
    @Json.SerializeNulls
    static class NullableOverrideOnField {
        @Json.SerializeNulls(false)
        String field = null;
        String field2 = null;
    }

    @Json.Entity
    @Json.SerializeNulls
    static class NullableOverrideOnMethod {
        String field = null;
        String field2 = null;

        @Json.SerializeNulls(false)
        public String field() {
            return field;
        }
    }

    @Json.SerializeNulls
    static class NullableParent {
    }

    @Json.Entity
    static class NullableChild extends NullableParent {
        String field = null;
    }

    @Json.Entity
    @Json.SerializeNulls(false)
    static class NonNullableChild extends NullableParent {
        String field = null;
    }

}
