package io.helidon.builder.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class MethodTest {

    private static final ImportOrganizer DEFAULT_IMPORTS = ImportOrganizer.builder()
            .packageName("io.helidon.builder.model")
            .typeName("SomeTestClass")
            .build();

    @Test
    public void testTypeReplacement() {
        String expected = """
                public void testClass() {
                    java.lang.String var1 = "hi";
                    String var2 = null;
                }""";

        ImportOrganizer importOrganizer = ImportOrganizer.builder()
                .addImport(String.class)
                .addImport(Map.class)
                .addImport("io.helidon.builder.model.String")
                .packageName("io.helidon.builder.model")
                .typeName("SomeTestClass")
                .get();
        Method method = Method.builder()
                .name("testClass")
                .className(String.class.getName())
                .addLine(" var1 = \"hi\";")
                .className("io.helidon.builder.model.String")
                .addLine(" var2 = null;")
                .addLine("@java.util.Map@<@java.lang.String@, @java.lang.String@> something;")
                .build();

        String generatedMethod = generateMethod(method, importOrganizer);
        System.out.println(generatedMethod);
        assertThat(generatedMethod, is(expected));
    }

    @Test
    public void testMethodBodyTypeImports() {
        String expected = """
                public void testClass() {
                    java.lang.String var1 = "hi";
                    String var2 = null;
                }""";

        ImportOrganizer.Builder builder = ImportOrganizer.builder()
                .packageName("io.helidon.builder.model")
                .typeName("SomeTestClass");
        Method method = Method.builder()
                .name("testClass")
                .className(String.class.getName())
                .addLine(" var1 = \"hi\";")
                .className("io.helidon.builder.model.String")
                .addLine(" var2 = null;")
                .addLine("@java.util.Map@<@java.lang.String@, @java.lang.String@> something;")
                .build();
        method.addImports(builder);
        ImportOrganizer importOrganizer = builder.build();

        String generatedMethod = generateMethod(method, importOrganizer);
        System.out.println(generatedMethod);
        assertThat(generatedMethod, is(expected));
    }

    private String generateMethod(Method method, ImportOrganizer importOrganizer) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            try (OutputStreamWriter writer = new OutputStreamWriter(outputStream)) {
                method.writeComponent(new ModelWriter(writer, "    "), Set.of(), importOrganizer);
            }
            return outputStream.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
