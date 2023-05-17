package io.helidon.builder.processor.tools.model.newModel;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;


public final class GenericType extends AbstractType {

    private final List<Type> typeParams;

    GenericType(Builder builder) {
        super(builder);
        this.typeParams = List.copyOf(builder.typeParams);
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
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
                parameter.writeComponent(writer, declaredTokens, imports);
            }
            writer.write(">");
        }
        if (isArray()) {
            writer.write("[]");
        }
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        typeParams.forEach(type -> type.addImports(imports));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        GenericType that = (GenericType) o;
        return Objects.equals(typeParams, that.typeParams);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), typeParams);
    }

    public static final class Builder extends AbstractType.Builder<Builder, GenericType> {

        private final List<Type> typeParams = new ArrayList<>();

        Builder(String type) {
            super(type);
        }

        @Override
        public GenericType build() {
            commonBuildLogic();
            return new GenericType(this);
        }

        public Builder addParam(String typeName) {
            return addParam(Type.exact(typeName));
        }

        public Builder addParam(Class<?> type) {
            return addParam(Type.exact(type));
        }

        public Builder addParam(Type type) {
            this.typeParams.add(type);
            return this;
        }
    }
}
