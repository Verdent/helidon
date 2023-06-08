package io.helidon.builder.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;

public class FieldTest {

    @Test
    public void testFieldDefaultValue() {
        String expected = "private List<String> fieldName = List.copyOf(new ArrayList());";

        ImportOrganizer.Builder builder = ImportOrganizer.builder()
                .packageName("io.helidon.builder.model")
                .typeName("SomeTestClass");
        Field field = Field.builder()
                .type(Type.generic()
                              .type(List.class)
                              .addParam(String.class)
                              .build())
                .name("fieldName")
                .defaultValue("@java.util.List@.copyOf(new @java.util.ArrayList@())")
                .build();
        field.addImports(builder);
        ImportOrganizer importOrganizer = builder.build();

        String generatedField = generateField(field, importOrganizer);

        assertThat(generatedField, is(expected));
        assertThat(importOrganizer.imports().size(), is(2));
        assertThat(importOrganizer.imports(), containsInAnyOrder(List.class.getName(), ArrayList.class.getName()));
    }

    @Test
    public void testFieldDefaultValueWithConflictingClasses() {
        String expected = "private java.util.List<String> fieldName = java.util.List.copyOf(new java.util.ArrayList());";

        ImportOrganizer.Builder builder = ImportOrganizer.builder()
                //These two classes are in the same package as the created dummy class. Therefore, they take
                //precedence over the ones from java.util
                .addImport("io.helidon.builder.model.List")
                .addImport("io.helidon.builder.model.ArrayList")
                .packageName("io.helidon.builder.model")
                .typeName("SomeTestClass");
        Field field = Field.builder()
                .type(Type.generic()
                              .type(List.class)
                              .addParam(String.class)
                              .build())
                .name("fieldName")
                .defaultValue("@java.util.List@.copyOf(new @java.util.ArrayList@())")
                .build();
        field.addImports(builder);
        ImportOrganizer importOrganizer = builder.build();

        String generatedField = generateField(field, importOrganizer);

        assertThat(generatedField, is(expected));
        assertThat(importOrganizer.imports().size(), is(0));
        assertThat(importOrganizer.forcedFullImports().size(), is(2));
        assertThat(importOrganizer.forcedFullImports(), containsInAnyOrder(List.class.getName(), ArrayList.class.getName()));
    }

    private String generateField(Field field, ImportOrganizer importOrganizer) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            try (OutputStreamWriter writer = new OutputStreamWriter(outputStream)) {
                field.writeComponent(new ModelWriter(writer, "    "), Set.of(), importOrganizer);
            }
            return outputStream.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
