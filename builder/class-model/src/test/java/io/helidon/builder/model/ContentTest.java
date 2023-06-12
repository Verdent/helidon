package io.helidon.builder.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;

public class ContentTest {

    private static final ImportOrganizer DEFAULT_IMPORTS = ImportOrganizer.builder()
            .packageName("io.helidon.builder.model")
            .typeName("SomeTestClass")
            .build();

    @Test
    public void testAutomaticPadding() {
        String expected = """
                if (true) {
                    System.out.println()
                }""";

        ImportOrganizer.Builder builder = ImportOrganizer.builder()
                .packageName("io.helidon.builder.model")
                .typeName("SomeTestClass");
        Content content = Content.builder()
                .addLine("if (true) {")
                .addLine("System.out.println();")
                .addLine("}")
                .build();
        content.addImports(builder);
        ImportOrganizer importOrganizer = builder.build();

        String generatedMethod = generateMethod(content, importOrganizer);
        assertThat(generatedMethod, is(expected));
    }

    @Test
    public void testMethodBodyImports() {
        String expected = "Map<String, SomeTestClass> someMap;";

        ImportOrganizer.Builder builder = ImportOrganizer.builder()
                .packageName("io.helidon.builder.model")
                .typeName("SomeTestClass");
        Content content = Content.builder()
                .addLine("@java.util.Map@<@java.lang.String@, @my.test.SomeTestClass@> someMap;")
                .build();
        content.addImports(builder);
        ImportOrganizer importOrganizer = builder.build();

        String generatedMethod = generateMethod(content, importOrganizer);
        assertThat(generatedMethod, is(expected));
        assertThat(importOrganizer.imports(), containsInAnyOrder(Map.class.getName(), "my.test.SomeTestClass"));
    }

    private String generateMethod(Content content, ImportOrganizer importOrganizer) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            try (OutputStreamWriter writer = new OutputStreamWriter(outputStream)) {
                content.writeBody(new ModelWriter(writer, "    "), importOrganizer);
            }
            return outputStream.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}
