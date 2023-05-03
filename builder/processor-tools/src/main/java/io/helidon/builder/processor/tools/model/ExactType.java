package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

public final class ExactType extends AbstractType {

    ExactType(Builder builder) {
        super(builder);
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        String typeName = imports.typeName(this, includeImport());
        writer.write(typeName);
        if (isArray()) {
            writer.write("[]");
        }
    }

    public static final class Builder extends AbstractType.Builder<Builder> {

        Builder(String type) {
            super(type);
        }

        @Override
        public Type build() {
            commonBuildLogic();
            return new ExactType(this);
        }

    }

}
