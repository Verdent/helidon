package io.helidon.builder.processor.tools.model;

/**
 * TODO javadoc
 */
public class InnerClass extends AbstractClass {

    InnerClass(Builder builder) {
        super(builder);
    }

    public static Builder builder(String className) {
        return new Builder(className);
    }

    void addImports(ImportOrganizer.Builder imports) {
        fields().values().forEach(field -> field.addImports(imports));
        staticFields().values().forEach(field -> field.addImports(imports));
        methods().values().forEach(method -> method.addImports(imports));
        interfaces().forEach(imp -> imp.addImports(imports));
        if (inheritance() != null) {
            inheritance().addImports(imports);
        }
        annotations().forEach(annotation -> annotation.addImports(imports));
        constructors().forEach(constructor -> constructor.addImports(imports));
        genericParameters().forEach(param -> param.addImports(imports));
    }

    public static class Builder extends AbstractClass.Builder<InnerClass, Builder> {

        Builder(String name) {
            super(name);
        }

        @Override
        public InnerClass build() {
            commonBuildLogic();
            return new InnerClass(this);
        }

        public Builder isStatic(boolean isStatic) {
            return super.isStatic(isStatic);
        }

    }
}
