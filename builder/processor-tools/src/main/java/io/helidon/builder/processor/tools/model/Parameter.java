package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

/**
 * TODO javadoc
 */
public class Parameter extends AbstractAnnotatable {

    private final boolean optional;

    private Parameter(Builder builder) {
        super(builder);
        this.optional = builder.optional;
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

    public static Builder builder(String name, Class<?> type) {
        return new Builder(name, Type.create(type));
    }

    public static Builder builder(String name, Type type) {
        return new Builder(name, type);
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        type().writeComponent(writer, declaredTokens, imports);
        if (optional) {
            writer.write("...");
        }
        writer.write(" " + name());
    }

    @Override
    public String toString() {
        return "Parameter{type=" + type().typeName() + ", simpleType=" + type().simpleTypeName() + ", name=" + name() + "}";
    }

    public static class Builder extends AbstractAnnotatable.Builder<Parameter, Builder> {

        private boolean optional = false;

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

    }
}
