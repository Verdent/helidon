package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.io.Writer;
import java.util.Objects;

public class ClassModel extends AbstractClass {

    private final String packageName;
    private final ImportOrganizer imports;

    private ClassModel(Builder builder) {
        super(builder);
        this.packageName = builder.packageName;
        this.imports = builder.imports.build();
    }

    public static Builder builder(String packageName, String name) {
        return new Builder(packageName, name);
    }

    public void saveToFile(Writer writer) throws IOException {
        ModelWriter innerWriter = new ModelWriter(writer, "    ");
        if (packageName != null && !packageName.isEmpty()) {
            innerWriter.write("package " + packageName + ";\n\n");
        }
        imports.writeImports(innerWriter);
        imports.writeStaticImports(innerWriter);
        writeComponent(innerWriter, imports);

    }

    public static class Builder extends AbstractClass.Builder<ClassModel, Builder> {
        private final ImportOrganizer.Builder imports;
        private final String packageName;

        private Builder(String packageName, String name) {
            super(name);
            this.packageName = Objects.requireNonNull(packageName);
            this.imports = ImportOrganizer.builder(packageName, name);
        }

        public ClassModel build() {
            commonBuildLogic();
            fields().values().forEach(field -> field.addImports(imports));
            staticFields().values().forEach(field -> field.addImports(imports));
            methods().values().forEach(method -> method.addImports(imports));
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
            imports.addImport(Type.create(importName));
            return this;
        }

        public Builder addStaticImport(String staticImport) {
            imports.addStaticImport(staticImport);
            return this;
        }

        public Builder addInnerClass(InnerClass innerClass) {
            return super.addInnerClass(innerClass);
        }

        public ImportOrganizer.Builder imports() {
            return imports;
        }

    }

}
