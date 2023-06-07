package io.helidon.builder.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
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
                .addLine("@java.util.Map@<@java.lang.String@, @java.lang.String@> something;")
                .addLine("if (true) {")
                .addLine("System.out.println();")
                .addLine("}")
                .build();
        content.addImports(builder);
        ImportOrganizer importOrganizer = builder.build();

        String generatedMethod = generateMethod(content, importOrganizer);
        System.out.println(generatedMethod);
        assertThat(generatedMethod, is(expected));
    }

    private String generateMethod(Content content, ImportOrganizer importOrganizer) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            try (OutputStreamWriter writer = new OutputStreamWriter(outputStream)) {
                content.writeBody(new ModelWriter(writer, "    "), importOrganizer, false);
            }
            return outputStream.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}
