package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class GeneralBuilderSupportTest {

    private static final JsonBinding HELIDON = JsonBinding.create();

    @Test
    public void testBuilderSupport() {
        String json = """
                {
                    "value" : "test"
                }""";

        TestPojoWithBuilder deserialized = HELIDON.deserialize(json, TestPojoWithBuilder.class);
        assertThat(deserialized.value(), is("test"));
    }

    @Test
    public void testBuilderWithNamePrefix() {
        String json = """
                {
                    "value" : "test"
                }""";

        TestPojoWithBuilderNamePrefix deserialized = HELIDON.deserialize(json, TestPojoWithBuilderNamePrefix.class);
        assertThat(deserialized.value(), is("test"));
    }

    @Test
    public void testBuilderWithDifferentBuildMethod() {
        String json = """
                {
                    "value" : "test",
                    "value2" : "test2"
                }""";

        TestPojoWithSetterAndBuilder deserialized = HELIDON.deserialize(json, TestPojoWithSetterAndBuilder.class);
        assertThat(deserialized.value(), is("test"));
        assertThat(deserialized.value2(), is("test2"));
    }

    @Json.Entity
    @Json.BuilderInfo(TestPojoWithBuilder.Builder.class)
    public static class TestPojoWithBuilder {

        @Json.Required
        private final String value;

        private TestPojoWithBuilder(Builder builder) {
            value = builder.value;
        }

        public String value() {
            return value;
        }

        public static class Builder {

            private String value;

            public Builder value(String value) {
                this.value = value;
                return this;
            }

            public TestPojoWithBuilder build() {
                return new TestPojoWithBuilder(this);
            }
        }
    }

    @Json.Entity
    @Json.BuilderInfo(value = TestPojoWithBuilderNamePrefix.Builder.class, methodPrefix = "with")
    static class TestPojoWithBuilderNamePrefix {

        private final String value;

        private TestPojoWithBuilderNamePrefix(Builder builder) {
            value = builder.value;
        }

        public String value() {
            return value;
        }

        static class Builder {

            private String value;

            public Builder withValue(String value) {
                this.value = value;
                return this;
            }

            public TestPojoWithBuilderNamePrefix build() {
                return new TestPojoWithBuilderNamePrefix(this);
            }
        }

    }

    @Json.Entity
    @Json.BuilderInfo(value = TestPojoWithBuilderDifferentBuildMethod.Builder.class, buildMethod = "create")
    static class TestPojoWithBuilderDifferentBuildMethod {

        private final String value;

        private TestPojoWithBuilderDifferentBuildMethod(Builder builder) {
            value = builder.value;
        }

        public String value() {
            return value;
        }

        static class Builder {

            private String value;

            public Builder value(String value) {
                this.value = value;
                return this;
            }

            public TestPojoWithBuilderDifferentBuildMethod create() {
                return new TestPojoWithBuilderDifferentBuildMethod(this);
            }
        }

    }

    @Json.Entity
    @Json.BuilderInfo(value = TestPojoWithSetterAndBuilder.Builder.class)
    static class TestPojoWithSetterAndBuilder {

        private final String value;
        private String value2;

        private TestPojoWithSetterAndBuilder(Builder builder) {
            value = builder.value;
        }

        public String value() {
            return value;
        }

        public String value2() {
            return value2;
        }

        public void value2(String value2) {
            this.value2 = value2;
        }

        static class Builder {

            private String value;

            public Builder value(String value) {
                this.value = value;
                return this;
            }

            public TestPojoWithSetterAndBuilder build() {
                return new TestPojoWithSetterAndBuilder(this);
            }
        }
    }


}
