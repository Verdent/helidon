package io.helidon.builder.processor.tools.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

public class ClassModel extends AbstractClass {

    private final String packageName;
    private final String licenseHeader;
    private final ImportOrganizer imports;

    private ClassModel(Builder builder) {
        super(builder);
        this.licenseHeader = builder.licenseHeader;
        this.packageName = builder.packageName;
        this.imports = builder.imports.build();
    }

    public static Builder builder(String packageName, String name) {
        return new Builder(packageName, name);
    }

    public void saveToFile(Writer writer) throws IOException {
        ModelWriter innerWriter = new ModelWriter(writer, "    ");
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
            innerWriter.write("package " + packageName + ";\n\n");
        }
        imports.writeImports(innerWriter);
        imports.writeStaticImports(innerWriter);
        writeComponent(innerWriter, Set.of(),imports);

    }

    @Override
    public String toString() {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            try (OutputStreamWriter writer = new OutputStreamWriter(outputStream)) {
                saveToFile(writer);
            }
            return outputStream.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static class Builder extends AbstractClass.Builder<ClassModel, Builder> {
        private final ImportOrganizer.Builder imports;
        private final String packageName;
        private String licenseHeader;

        private Builder(String packageName, String name) {
            super(name);
            this.packageName = Objects.requireNonNull(packageName);
            this.imports = ImportOrganizer.builder(packageName, name);
        }

        public ClassModel build() {
            commonBuildLogic();
            fields().values().forEach(field -> field.addImports(imports));
            staticFields().values().forEach(field -> field.addImports(imports));
            methods().forEach(method -> method.addImports(imports));
            staticMethod().forEach(method -> method.addImports(imports));
            interfaces().forEach(imp -> imp.addImports(imports));
            if (inheritance() != null) {
                inheritance().addImports(imports);
            }
            annotations().forEach(annotation -> annotation.addImports(imports));
            innerClasses().values().forEach(innerClass -> innerClass.addImports(imports));
            constructors().forEach(constructor -> constructor.addImports(imports));
            genericParameters().forEach(param -> param.addImports(imports));
            return new ClassModel(this);
        }

        @Override
        public Builder accessModifier(AccessModifier accessModifier) {
            if (accessModifier == AccessModifier.PRIVATE) {
                throw new IllegalArgumentException("Outer class cannot be private!");
            }
            return super.accessModifier(accessModifier);
        }

        public Builder addImport(Class<?> typeImport) {
            return addImport(typeImport.getName());
        }

        public Builder addImport(String importName) {
            imports.addImport(Type.exact(importName));
            return this;
        }

        public Builder addStaticImport(String staticImport) {
            imports.addStaticImport(staticImport);
            return this;
        }

        public Builder licenseHeader(String licenseHeader) {
            this.licenseHeader = licenseHeader;
            return this;
        }

        public Builder innerClassBuilder(String className, Consumer<InnerClass.Builder> innerClassConsumer) {
            InnerClass.Builder builder = InnerClass.builder(className, imports);
            innerClassConsumer.accept(builder);
            return addInnerClass(builder.build());
        }

        @Deprecated
        public InnerClass.Builder innerClassBuilder(String className) {
            return InnerClass.builder(className, imports);
        }

        ImportOrganizer.Builder imports() {
            return imports;
        }

    }

}
