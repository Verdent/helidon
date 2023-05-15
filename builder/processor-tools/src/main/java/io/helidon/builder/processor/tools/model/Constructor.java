package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

public class Constructor extends AbstractMethod {

    private Constructor(Builder builder) {
        super(builder);
    }

    @Deprecated
    public static Builder builder(String type) {
        return new Builder(Type.exact(type));
    }

    public static Constructor create(String type) {
        return builder(type).build();
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        if (javadoc().shouldGenerate(accessModifier())) {
            javadoc().writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        for (Annotation annotation : annotations()) {
            annotation.writeComponent(writer, declaredTokens, imports);
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
            parameter.writeComponent(writer, declaredTokens, imports);
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
