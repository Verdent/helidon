package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class GenericType extends AbstractType {

    private final List<Type> typeParams;

    GenericType(Builder builder) {
        super(builder);
        this.typeParams = List.copyOf(builder.typeParams);
    }

    @Override
    void writeComponent(ModelWriter writer, ImportOrganizer imports) throws IOException {
        String typeName = imports.typeName(this, includeImport());
        writer.write(typeName);
        if (!typeParams.isEmpty()) {
            writer.write("<");
            boolean first = true;
            for (Type parameter : typeParams) {
                if (first) {
                    first = false;
                } else {
                    writer.write(", ");
                }
                parameter.writeComponent(writer, imports);
            }
            writer.write(">");
        }
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        typeParams.forEach(type -> type.addImports(imports));
    }

    public static final class Builder extends AbstractType.Builder<Builder> {

        private final List<Type> typeParams = new ArrayList<>();

        Builder(String type) {
            super(type);
        }

        @Override
        public Type build() {
            commonBuildLogic();
            return new GenericType(this);
        }

        public Builder addParam(String typeName) {
            return addParam(Type.create(typeName));
        }

        public Builder addParam(Class<?> type) {
            return addParam(Type.create(type));
        }

        public Builder addParam(Type type) {
            this.typeParams.add(type);
            return this;
        }
    }
}
