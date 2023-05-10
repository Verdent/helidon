package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

/**
 * TODO javadoc
 */
public class Parameter extends AbstractAnnotatable {

    private final boolean optional;
    private final String description;

    private Parameter(Builder builder) {
        super(builder);
        this.optional = builder.optional;
        this.description = builder.description;
    }

    public static Parameter create(String name, Class<?> type) {
        return create(name, Type.create(type));
    }

    public static Parameter create(String name, String typeName) {
        return create(name, Type.create(typeName));
    }

    public static Parameter create(String name, Type type) {
        return builder(name, type).build();
    }

    public static Builder builder(String name, String typeName) {
        return new Builder(name, Type.create(typeName));
    }
    public static Builder builder(String name, Class<?> type) {
        return new Builder(name, Type.create(type));
    }

    public static Builder builder(String name, Type type) {
        return new Builder(name, type);
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        for (Annotation annotation : annotations()) {
            annotation.writeComponent(writer, declaredTokens, imports);
            writer.write(" ");
        }
        type().writeComponent(writer, declaredTokens, imports);
        if (optional) {
            writer.write("...");
        }
        writer.write(" " + name());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Parameter parameter = (Parameter) o;
        return optional == parameter.optional && type().equals(parameter.type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(optional);
    }

    @Override
    public String toString() {
        return "Parameter{type=" + type().typeName() + ", simpleType=" + type().simpleTypeName() + ", name=" + name() + "}";
    }

    String description() {
        return description;
    }

    public static class Builder extends AbstractAnnotatable.Builder<Parameter, Builder> {

        private boolean optional = false;
        private String description = "";

        private Builder(String name, Type type) {
            super(name, type);
        }

        public Parameter build() {
            return new Parameter(this);
        }

        public Builder optional(boolean optional) {
            this.optional = optional;
            return this;
        }

        @Override
        public Builder description(String description) {
            this.description = description;
            return this;
        }
    }
}
