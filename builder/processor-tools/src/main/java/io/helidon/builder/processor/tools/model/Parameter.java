package io.helidon.builder.processor.tools.model;

import java.io.IOException;

/**
 * TODO javadoc
 */
public class Parameter extends AbstractAnnotatable {

    private Parameter(Builder builder) {
        super(builder);
    }

    public static Parameter create(String name, Class<?> type) {
        return create(name, Type.create(type));
    }

    public static Parameter create(String name, String typeName) {
        return create(name, Type.create(typeName));
    }

    public static Parameter create(String name, Type type) {
        return new Builder(name, type).build();
    }

    @Override
    void writeComponent(ModelWriter writer, ImportOrganizer imports) throws IOException {
        type().writeComponent(writer, imports);
        writer.write(" " + name());
    }

    @Override
    public String toString() {
        return "Parameter{type=" + type().typeName() + ", simpleType=" + type().simpleTypeName() + ", name=" + name() + "}";
    }

    public static class Builder extends AbstractAnnotatable.Builder<Parameter, Builder> {

        private Builder(String name, Type type) {
            super(name, type);
        }

        public Parameter build() {
            return new Parameter(this);
        }

    }
}
