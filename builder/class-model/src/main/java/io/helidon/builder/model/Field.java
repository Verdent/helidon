package io.helidon.builder.model;

import java.io.IOException;
import java.util.Set;

import io.helidon.common.types.TypeName;

/**
 * TODO javadoc
 */
public class Field extends AnnotatableComponent implements Comparable<Field> {

    private final Content defaultValue;
    private final boolean isFinal;
    private final boolean isStatic;

    public Field(Builder builder) {
        super(builder);
        this.defaultValue = builder.defaultValueBuilder.build();
        this.isFinal = builder.isFinal;
        this.isStatic = builder.isStatic;
    }

    public static Builder builder() {
        return new Builder().accessModifier(AccessModifier.PRIVATE);
    }

    public static Field create(String name, Class<?> type) {
        return builder().name(name)
                .type(type)
                .build();
    }

    public static Field create(String name, String typeName) {
        return builder().name(name)
                .type(typeName)
                .build();
    }

    public static Field create(String name, Type type) {
        return builder().name(name)
                .type(type)
                .build();
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        if (javadoc().generate()) {
            javadoc().writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        for (Annotation annotation : annotations()) {
            annotation.writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        if (AccessModifier.PACKAGE_PRIVATE != accessModifier()) {
            writer.write(accessModifier().modifierName());
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
        if (defaultValue.hasBody()) {
            writer.write(" = ");
            defaultValue.writeBody(writer, imports);
            writer.write(";");
        } else {
            writer.write(";");
        }
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        type().addImports(imports);
        defaultValue.addImports(imports);
    }

    boolean isStatic() {
        return isStatic;
    }

    @Override
    public int compareTo(Field other) {
        if (accessModifier() == other.accessModifier()) {
            if (isFinal == other.isFinal) {
                if (type().simpleTypeName().equals(other.type().simpleTypeName())) {
                    return name().compareTo(other.name());
                }
                return type().simpleTypeName().compareTo(other.type().simpleTypeName());
            }
            //final fields should be before non-final
            return Boolean.compare(other.isFinal, isFinal);
        } else {
            return accessModifier().compareTo(other.accessModifier());
        }
    }

    @Override
    public String toString() {
        if (defaultValue != null) {
            return accessModifier().modifierName() + " " + type().typeName() + " " + name() + " = " + defaultValue;
        }
        return accessModifier().modifierName() + " " + type().typeName() + " " + name();
    }

    public static class Builder extends AnnotatableComponent.Builder<Builder, Field> {

        private final Content.Builder defaultValueBuilder = Content.builder();
        private boolean isFinal = false;
        private boolean isStatic = false;

        private Builder() {
        }

        public Field build() {
            return new Field(this);
        }

        public Builder defaultValue(String defaultValue) {
            if (type().typeName().equals(String.class.getName())
                    && !type().isArray()
                    && !defaultValue.startsWith("\"")
                    && !defaultValue.endsWith("\"")) {
                defaultValueBuilder.content("\"" + defaultValue + "\"");
            } else {
                defaultValueBuilder.content(defaultValue);
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

        @Override
        public Builder type(TypeName type) {
            return super.type(type);
        }

        @Override
        public Builder type(String type) {
            return super.type(type);
        }

        @Override
        public Builder type(Class<?> type) {
            return super.type(type);
        }

        @Override
        public Builder type(Type type) {
            return super.type(type);
        }

        @Override
        public Builder accessModifier(AccessModifier accessModifier) {
            return super.accessModifier(accessModifier);
        }
    }
}
