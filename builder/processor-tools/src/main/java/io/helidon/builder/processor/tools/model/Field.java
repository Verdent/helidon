package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

/**
 * TODO javadoc
 */
public class Field extends AbstractAnnotatable {

    private final String defaultValue;
    private final boolean isFinal;
    private final boolean isStatic;
    private final AccessModifier accessModifier;

    public Field(Builder builder) {
        super(builder);
        this.defaultValue = builder.defaultValue;
        this.accessModifier = builder.accessModifier;
        this.isFinal = builder.isFinal;
        this.isStatic = builder.isStatic;
    }

    public static Builder builder(String name, Class<?> type) {
        return new Builder(name, Type.create(type));
    }
    public static Builder builder(String name, String type) {
        return new Builder(name, Type.create(type));
    }

    public static Builder builder(String name, Type type) {
        return new Builder(name, type);
    }

    public static Field create(String name, Class<?> type) {
        return builder(name, type).build();
    }

    public static Field create(String name, String typeName) {
        return builder(name, typeName).build();
    }

    public static Field create(String name, Type type) {
        return builder(name, type).build();
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        if (javadoc().shouldGenerate(accessModifier)) {
            javadoc().writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        for (Annotation annotation : annotations()) {
            annotation.writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        if (AccessModifier.PACKAGE_PRIVATE != accessModifier) {
            writer.write(accessModifier.modifierName());
            writer.write(" ");
        }
        if (isStatic) {
            writer.write("static ");
        }
        if (isFinal) {
            writer.write("final ");
        }
        type().writeComponent(writer, declaredTokens, imports);
        writer.write(" ");
        writer.write(name());
        if (defaultValue == null) {
            writer.write(";");
        } else {
            writer.write(" = " + defaultValue + ";");
        }
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        type().addImports(imports);
    }

    boolean isStatic() {
        return isStatic;
    }

    public static class Builder extends AbstractAnnotatable.Builder<Field, Builder> {

        private String defaultValue;
        private boolean isFinal = false;
        private boolean isStatic = false;
        private AccessModifier accessModifier = AccessModifier.PRIVATE;

        private Builder(String name, Type type) {
            super(name, type);
        }

        public Field build() {
            return new Field(this);
        }

        public Builder accessModifier(AccessModifier accessModifier) {
            this.accessModifier = accessModifier;
            return this;
        }

        public Builder defaultValue(String defaultValue) {
            if (type().typeName().equals(String.class.getName())
                    && !type().isArray()
                    && !defaultValue.startsWith("\"")
                    && !defaultValue.endsWith("\"")) {
                this.defaultValue = "\"" + defaultValue + "\"";
            } else {
                this.defaultValue = defaultValue;
            }
            return this;
        }

        public Builder isFinal(boolean isFinal) {
            this.isFinal = isFinal;
            return this;
        }

        public Builder isStatic(boolean isStatic) {
            this.isStatic = isStatic;
            return this;
        }

    }
}
