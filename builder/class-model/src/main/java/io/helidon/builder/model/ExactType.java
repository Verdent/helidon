package io.helidon.builder.model;

import java.io.IOException;
import java.util.Set;

public final class ExactType extends AbstractType {

    ExactType(Builder builder) {
        super(builder);
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        String typeName = imports.typeName(this);
        writer.write(typeName);
        if (isArray()) {
            writer.write("[]");
        }
    }

    public static final class Builder extends AbstractType.Builder<Builder, ExactType> {

        Builder() {
        }

        @Override
        public ExactType build() {
            if (typeName() == null) {
                throw new ClassModelException("Type value needs to be set");
            }
            return new ExactType(this);
        }

    }

}
