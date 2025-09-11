package io.helidon.jsonschema.schema;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SchemaIntegerTest {

    @Test
    void testBoundaries() {
        SchemaInteger schemaInteger = SchemaInteger.builder()
                .minimum(0)
                .maximum(1)
                .build();
        assertThat(schemaInteger.minimum().isPresent(), is(true));
        assertThat(schemaInteger.maximum().isPresent(), is(true));
        assertThat(schemaInteger.exclusiveMinimum().isPresent(), is(false));
        assertThat(schemaInteger.exclusiveMaximum().isPresent(), is(false));
        assertThat(schemaInteger.multipleOf().isPresent(), is(false));
        assertThat(schemaInteger.minimum().get(), is(0L));
        assertThat(schemaInteger.maximum().get(), is(1L));
    }

    @Test
    void testBoundariesExclusive() {
        SchemaInteger schemaInteger = SchemaInteger.builder()
                .exclusiveMinimum(0)
                .exclusiveMaximum(1)
                .build();
        assertThat(schemaInteger.minimum().isPresent(), is(false));
        assertThat(schemaInteger.maximum().isPresent(), is(false));
        assertThat(schemaInteger.exclusiveMinimum().isPresent(), is(true));
        assertThat(schemaInteger.exclusiveMaximum().isPresent(), is(true));
        assertThat(schemaInteger.multipleOf().isPresent(), is(false));
        assertThat(schemaInteger.exclusiveMinimum().get(), is(0L));
        assertThat(schemaInteger.exclusiveMaximum().get(), is(1L));
    }

    @Test
    void testBoundariesMixed() {
        assertThrows(JsonSchemaException.class, () -> SchemaInteger.builder()
                .minimum(1)
                .exclusiveMinimum(1)
                .build());

        assertThrows(JsonSchemaException.class, () -> SchemaInteger.builder()
                .maximum(1)
                .exclusiveMaximum(1)
                .build());
    }

    @Test
    void testLowerMaximum() {
        assertThrows(JsonSchemaException.class, () -> SchemaInteger.builder()
                .minimum(2)
                .maximum(1)
                .build());

        assertThrows(JsonSchemaException.class, () -> SchemaInteger.builder()
                .exclusiveMinimum(2)
                .exclusiveMaximum(1)
                .build());

        assertThrows(JsonSchemaException.class, () -> SchemaInteger.builder()
                .exclusiveMinimum(2)
                .maximum(1)
                .build());

        assertThrows(JsonSchemaException.class, () -> SchemaInteger.builder()
                .minimum(2)
                .exclusiveMaximum(1)
                .build());
    }

}
