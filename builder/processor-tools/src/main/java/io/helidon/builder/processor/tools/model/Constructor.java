package io.helidon.builder.processor.tools.model;

import java.io.IOException;

public class Constructor extends AbstractMethod {

    private Constructor(Builder builder) {
        super(builder);
    }

    public static Builder builder(String type) {
        return new Builder(Type.create(type));
    }

    public static Constructor create(String type) {
        return builder(type).build();
    }

    @Override
    void writeComponent(ModelWriter writer, ImportOrganizer imports) throws IOException {
        for (Annotation annotation : annotations()) {
            annotation.writeComponent(writer, imports);
            writer.write("\n");
        }
        if (AccessModifier.PACKAGE_PRIVATE != accessModifier()) {
            writer.write(accessModifier().modifierName() + " ");
        }
        String typeName = type().simpleTypeName();
        writer.write(typeName + "(");
        boolean first = true;
        for (Parameter parameter : parameters().values()) {
            if (first) {
                first = false;
            } else {
                writer.write(", ");
            }
            parameter.writeComponent(writer, imports);
        }
        writer.write(") {");
        if (!content().isEmpty()) {
            writeBody(writer);
        } else {
            writer.write("\n");
        }
        writer.write("}");
    }

    public static class Builder extends AbstractMethod.Builder<Constructor, Builder> {

        Builder(Type type) {
            super(null, type);
        }

        @Override
        public Constructor build() {
            return new Constructor(this);
        }
    }
}
