package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Tests serialization and deserialization of boolean values.
 */
public class BooleanTest {

    @Test
    public void testBooleanSerialization() throws Exception {
        BooleanModel booleanModel = new BooleanModel(true, false);

        String expected = "{\"field1\":true,\"field2\":false}";
        assertThat(JsonBinding.serialize(booleanModel), is(expected));
    }

    @Test
    public void testBooleanDeserializationFromBooleanAsStringValue() throws Exception {
        BooleanModel booleanModel = JsonBinding.deserialize("{\"field1\":\"true\",\"field2\":\"true\"}", BooleanModel.class);
        assertThat(booleanModel.field1, is(true));
        assertThat(booleanModel.field2, is(true));
    }

    @Test
    public void testBooleanDeserializationFromBooleanRawValue() throws Exception {
        BooleanModel booleanModel = JsonBinding.deserialize("{\"field1\":false,\"field2\":false}", BooleanModel.class);
        assertThat(booleanModel.field1, is(false));
        assertThat(booleanModel.field2, is(false));
    }

    @Test
    public void testRawBooleans() {
        Boolean bool = JsonBinding.deserialize("true", Boolean.class);
        assertThat(bool, is(true));
        bool = JsonBinding.deserialize("true", boolean.class);
        assertThat(bool, is(true));
        bool = JsonBinding.deserialize("false", Boolean.class);
        assertThat(bool, is(false));
        bool = JsonBinding.deserialize("false", boolean.class);
        assertThat(bool, is(false));
        bool = JsonBinding.deserialize("null", Boolean.class);
        assertThat(bool, nullValue());
        bool = JsonBinding.deserialize("null", boolean.class);
        assertThat(bool, is(false));

        String result = JsonBinding.serialize(true);
        assertThat(result, is("true"));
        result = JsonBinding.serialize(false);
        assertThat(result, is("false"));
    }

    @Test
    public void testBooleanArrays() {
        boolean[] primitives = {true, false};
        Boolean[] referenceTypes = {true, false};
        String arrayJson = "[true,false]";

        assertThat(JsonBinding.create().toJson(primitives), is(arrayJson));
        assertThat(JsonBinding.create().toJson(referenceTypes), is(arrayJson));

        assertThat(JsonBinding.deserialize(arrayJson, boolean[].class), is(primitives));
        assertThat(JsonBinding.deserialize(arrayJson, Boolean[].class), is(referenceTypes));
    }

    @Json.Entity
    public static class BooleanModel {
        public Boolean field1;
        public boolean field2;

        public BooleanModel() {
        }

        public BooleanModel(boolean field1, Boolean field2) {
            this.field2 = field2;
            this.field1 = field1;
        }
    }
}
