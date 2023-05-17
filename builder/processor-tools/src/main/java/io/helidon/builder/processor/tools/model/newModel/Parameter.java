package io.helidon.builder.processor.tools.model.newModel;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

import io.helidon.common.types.TypeName;

/**
 * TODO javadoc
 */
public class Parameter extends AnnotatableComponent {

    private final boolean optional;
    private final String description;

    private Parameter(Builder builder) {
        super(builder);
        this.optional = builder.optional;
        this.description = builder.description;
    }

    public static Parameter create(String name, Class<?> type) {
        return create(name, Type.exact(type));
    }

    public static Parameter create(String name, String typeName) {
        return create(name, Type.exact(typeName));
    }

    public static Parameter create(String name, Type type) {
        return builder().name(name)
                .type(type)
                .build();
    }

    public static Builder builder() {
        return new Builder();
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

    public static class Builder extends AnnotatableComponent.Builder<Builder, Parameter> {

        private boolean optional = false;
        private String description = "";

        private Builder() {
        }

        public Parameter build() {
            if (type() == null || name() == null) {
                throw new ClassModelException("Annotation parameter must have name and type set");
            }
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
    }
}
