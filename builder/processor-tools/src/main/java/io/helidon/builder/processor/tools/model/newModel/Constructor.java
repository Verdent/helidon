package io.helidon.builder.processor.tools.model.newModel;

import java.io.IOException;
import java.util.Set;

public final class Constructor extends AbstractMethod {

    private Constructor(Builder builder) {
        super(builder);
    }

    static Builder builder() {
        return new Builder();
    }

    static Constructor create(String type) {
        return builder().type(type).build();
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
            writer.write(accessModifier().modifierName() + " ");
        }
        String typeName = type().simpleTypeName();
        writer.write(typeName + "(");
        boolean first = true;
        for (Parameter parameter : parameters()) {
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

    public static final class Builder extends AbstractMethod.Builder<Builder, Constructor> {

        private Builder() {
        }

        @Override
        public Constructor build() {
            return new Constructor(this);
        }

    }
}
