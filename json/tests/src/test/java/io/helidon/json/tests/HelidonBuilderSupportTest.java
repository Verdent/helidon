package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class HelidonBuilderSupportTest {

    private static final JsonBinding HELIDON = JsonBinding.create();

    @Test
    public void testHelidonBuilderSupport() {
        String json = """
                {
                    "value" : "test"
                }""";

        TestPojoWithBuilder deserialized = HELIDON.deserialize(json, TestPojoWithBuilder.class);
        assertThat(deserialized.value(), is("test"));
    }

    @Json.Entity
    static class TestPojoWithBuilder {

        private final String value;

        private TestPojoWithBuilder(Builder builder) {
            value = builder.value;
        }

        static Builder builder() {
            return new Builder();
        }

        String value() {
            return value;
        }

        static class Builder implements io.helidon.common.Builder<Builder, TestPojoWithBuilder> {

            private String value;

            Builder value(String value) {
                this.value = value;
                return this;
            }

            @Override
            public TestPojoWithBuilder build() {
                return new TestPojoWithBuilder(this);
            }
        }
    }


}
