package io.helidon.builder.processor.tools.model;

/**
 * TODO javadoc
 */
public final class InnerClass extends AbstractClass {

    InnerClass(Builder builder) {
        super(builder);
    }

    static Builder builder(String className, ImportOrganizer.Builder imports) {
        return new Builder(className, imports);
    }

    void addImports(ImportOrganizer.Builder imports) {
        fields().forEach(field -> field.addImports(imports));
        staticFields().forEach(field -> field.addImports(imports));
        methods().forEach(method -> method.addImports(imports));
        staticMethods().forEach(method -> method.addImports(imports));
        interfaces().forEach(imp -> imp.addImports(imports));
        if (inheritance() != null) {
            inheritance().addImports(imports);
        }
        annotations().forEach(annotation -> annotation.addImports(imports));
        constructors().forEach(constructor -> constructor.addImports(imports));
        genericParameters().forEach(param -> param.addImports(imports));
    }

    public static class Builder extends AbstractClass.Builder<InnerClass, Builder> {

        private final ImportOrganizer.Builder imports;

        Builder(String name, ImportOrganizer.Builder imports) {
            super(name);
            this.imports = imports;
        }

        @Override
        public InnerClass build() {
            commonBuildLogic();
            return new InnerClass(this);
        }

        public Builder isStatic(boolean isStatic) {
            return super.isStatic(isStatic);
        }

        @Override
        public Builder addImport(String importName) {
            imports.addImport(importName);
            return this;
        }

    }
}
