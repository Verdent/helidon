package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AnnotationsTest {

    @Test
    public void testWithoutEntity() {
        assertThrows(IllegalStateException.class, () -> JsonBinding.serialize(new WithoutEntity()));
        assertThrows(IllegalStateException.class, () -> JsonBinding.deserialize("{}", WithoutEntity.class));
    }

    @Test
    public void testWithEntity() {
        String json = JsonBinding.serialize(new WithEntity());
        assertThat(json, is("{}"));

        WithEntity deserialize = JsonBinding.deserialize(json, WithEntity.class);
        assertThat(deserialize, notNullValue());
    }

    @Test
    public void testPropertyNameOnTheField() {
        PropertyNameChangeField entity = new PropertyNameChangeField();
        entity.property1 = "property1";
        entity.property2 = "property2";

        String json = JsonBinding.serialize(entity);
        assertThat(json, is("{\"property1\":\"property1\",\"prop2\":\"property2\"}"));

        PropertyNameChangeField deserialize = JsonBinding.deserialize(json, PropertyNameChangeField.class);
        assertThat(deserialize, notNullValue());
        assertThat(deserialize.property1, is("property1"));
        assertThat(deserialize.property2, is("property2"));
    }

    @Test
    public void testPropertyNameOnTheAccessor() {
        PropertyNameChangeAccessor entity = new PropertyNameChangeAccessor();
        entity.property1 = "property1";
        entity.property2 = "property2";

        String json = JsonBinding.serialize(entity);
        assertThat(json, is("{\"property1\":\"property1\",\"prop2\":\"property2\"}"));

        PropertyNameChangeAccessor deserialize = JsonBinding.deserialize(json, PropertyNameChangeAccessor.class);
        assertThat(deserialize, notNullValue());
        assertThat(deserialize.property1, nullValue());
        assertThat(deserialize.property2, nullValue());

        String toDeserialize = "{\"prop1\":\"property1\",\"property2\":\"property2\"}";
        deserialize = JsonBinding.deserialize(toDeserialize, PropertyNameChangeAccessor.class);
        assertThat(deserialize.property1, is("property1"));
        assertThat(deserialize.property2, is("property2"));
    }

    @Test
    public void testPropertyNameOverride() {
        PropertyNameOverride entity = new PropertyNameOverride();
        entity.property1 = "property1";
        entity.property2 = "property2";

        String json = JsonBinding.serialize(entity);
        assertThat(json, is("{\"myProperty1\":\"property1\",\"prop2\":\"property2\"}"));

        PropertyNameOverride deserialize = JsonBinding.deserialize(json, PropertyNameOverride.class);
        assertThat(deserialize, notNullValue());
        assertThat(deserialize.property1, nullValue());
        assertThat(deserialize.property2, nullValue());

        String toDeserialize = "{\"prop1\":\"property1\",\"myProperty2\":\"property2\"}";
        deserialize = JsonBinding.deserialize(toDeserialize, PropertyNameOverride.class);
        assertThat(deserialize.property1, is("property1"));
        assertThat(deserialize.property2, is("property2"));
    }

    static class WithoutEntity {
    }

    @Json.Entity
    static class WithEntity {
    }

    @Json.Entity
    static class PropertyNameChangeField {
        public String property1;
        @Json.Property("prop2")
        public String property2;
    }

    @Json.Entity
    static class PropertyNameChangeAccessor {
        private String property1;
        private String property2;

        public String getProperty1() {
            return property1;
        }

        @Json.Property("prop1")
        public void setProperty1(String property1) {
            this.property1 = property1;
        }

        @Json.Property("prop2")
        public String getProperty2() {
            return property2;
        }

        public void setProperty2(String property2) {
            this.property2 = property2;
        }
    }

    @Json.Entity
    static class PropertyNameOverride {
        @Json.Property("myProperty1")
        private String property1;
        @Json.Property("myProperty2")
        private String property2;

        public String getProperty1() {
            return property1;
        }

        @Json.Property("prop1")
        public void setProperty1(String property1) {
            this.property1 = property1;
        }

        @Json.Property("prop2")
        public String getProperty2() {
            return property2;
        }

        public void setProperty2(String property2) {
            this.property2 = property2;
        }
    }

}
