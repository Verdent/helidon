package io.helidon.jsonschema.schema;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SchemaTest {

    @Test
    public void testSchema() {
        Schema schema = Schema.builder()
                .rootObject(builder -> builder
                                  .putIntegerProperty("number", builder2 -> builder2.description("some number"))
                                  .putStringProperty("text", builder2 -> builder2.description("some text")))
                .build();
        SchemaObject root = schema.rootObject().orElseThrow();
        assertThat(root.properties().size(), is(2));
        assertThat(root.integerProperties().size(), is(1));
        assertThat(root.stringProperties().size(), is(1));
    }

    @Test
    public void testSchemaMultipleRoots() {
        assertThrows(SchemaException.class, () -> Schema.builder()
                .rootInteger(builder -> builder.multipleOf(1))
                .rootNumber(builder -> builder.multipleOf(1))
                .build());
    }

}
