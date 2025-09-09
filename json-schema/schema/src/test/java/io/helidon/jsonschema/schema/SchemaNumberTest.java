package io.helidon.jsonschema.schema;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SchemaNumberTest {

    @Test
    void testBoundaries() {
        SchemaNumber schemaNumber = SchemaNumber.builder()
                .minimum(0)
                .maximum(1)
                .build();
        assertThat(schemaNumber.minimum().isPresent(), is(true));
        assertThat(schemaNumber.maximum().isPresent(), is(true));
        assertThat(schemaNumber.exclusiveMinimum().isPresent(), is(false));
        assertThat(schemaNumber.exclusiveMaximum().isPresent(), is(false));
        assertThat(schemaNumber.multipleOf().isPresent(), is(false));
        assertThat(schemaNumber.minimum().get(), is(0));
        assertThat(schemaNumber.maximum().get(), is(1));
    }

    @Test
    void testBoundariesExclusive() {
        SchemaNumber schemaNumber = SchemaNumber.builder()
                .exclusiveMinimum(0)
                .exclusiveMaximum(1)
                .build();
        assertThat(schemaNumber.minimum().isPresent(), is(false));
        assertThat(schemaNumber.maximum().isPresent(), is(false));
        assertThat(schemaNumber.exclusiveMinimum().isPresent(), is(true));
        assertThat(schemaNumber.exclusiveMaximum().isPresent(), is(true));
        assertThat(schemaNumber.multipleOf().isPresent(), is(false));
        assertThat(schemaNumber.exclusiveMinimum().get(), is(0));
        assertThat(schemaNumber.exclusiveMaximum().get(), is(1));
    }

    @Test
    void testBoundariesMixed() {
        assertThrows(SchemaException.class, () -> SchemaNumber.builder()
                .minimum(1)
                .exclusiveMinimum(1)
                .build());

        assertThrows(SchemaException.class, () -> SchemaNumber.builder()
                .maximum(1)
                .exclusiveMaximum(1)
                .build());
    }

    @Test
    void testLowerMaximum() {
        assertThrows(SchemaException.class, () -> SchemaNumber.builder()
                .minimum(2)
                .maximum(1)
                .build());

        assertThrows(SchemaException.class, () -> SchemaNumber.builder()
                .exclusiveMinimum(2)
                .exclusiveMaximum(1)
                .build());

        assertThrows(SchemaException.class, () -> SchemaNumber.builder()
                .exclusiveMinimum(2)
                .maximum(1)
                .build());

        assertThrows(SchemaException.class, () -> SchemaNumber.builder()
                .minimum(2)
                .exclusiveMaximum(1)
                .build());
    }

}
