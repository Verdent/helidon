package io.helidon.builder.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Set;


public class ClassModel extends AbstractClass {

    public static final String PADDING_TOKEN = "<<padding>>";
    private final String packageName;
    private final String licenseHeader;
    //This has to be set after this object is constructed, if we want to use common addImports method
    private ImportOrganizer imports;

    private ClassModel(Builder builder) {
        super(builder);
        this.licenseHeader = builder.licenseHeader;
        this.packageName = builder.packageName;
    }

    public static ClassModel.Builder builder() {
        return new Builder();
    }

    public static ClassModel.Builder builder(String packageName, String name) {
        return new Builder()
                .packageName(packageName)
                .name(name);
    }

    public void saveToFile(Writer writer) throws IOException {
        saveToFile(writer, "    ");
    }

    public void saveToFile(Writer writer, String padding) throws IOException {
        ModelWriter innerWriter = new ModelWriter(writer, padding);
        writeComponent(innerWriter, Set.of(), imports);
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        if (licenseHeader != null) {
            String[] lines = licenseHeader.split("\n");
            if (lines.length > 1) {
                writer.write("/*\n");
                for (String line : lines) {
                    writer.write(" * " + line + "\n");
                }
                writer.write(" */\n\n");
            } else {
                if (!lines[0].startsWith("//")) {
                    writer.write("// ");
                }
                writer.write(lines[0] + "\n");
            }
        }
        if (packageName != null && !packageName.isEmpty()) {
            writer.write("package " + packageName + ";\n\n");
        }
        imports.writeImports(writer);
        imports.writeStaticImports(writer);
        super.writeComponent(writer, declaredTokens, imports);
    }

    @Override
    public String toString() {
        return toString("    ");
    }

    public String toString(String padding) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            try (OutputStreamWriter writer = new OutputStreamWriter(outputStream)) {
                saveToFile(writer, padding);
            }
            return outputStream.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static final class Builder extends AbstractClass.Builder<Builder, ClassModel> {

        private String packageName;
        private String licenseHeader;

        private Builder() {
        }

        @Override
        public ClassModel build() {
            if (packageName == null && name() == null) {
                throw new ClassModelException("Class need to have name and package specified");
            }
            ClassModel classModel = new ClassModel(this);
            ImportOrganizer.Builder importOrganizer = importOrganizer();
            classModel.addImports(importOrganizer);
            classModel.imports = importOrganizer.build();
            return classModel;
        }

        @Override
        public Builder accessModifier(AccessModifier accessModifier) {
            if (accessModifier == AccessModifier.PRIVATE) {
                throw new IllegalArgumentException("Outer class cannot be private!");
            }
            return super.accessModifier(accessModifier);
        }

        public Builder packageName(String packageName) {
            this.packageName = packageName;
            return this;
        }

        public Builder licenseHeader(String licenseHeader) {
            this.licenseHeader = licenseHeader;
            return this;
        }

    }

}
