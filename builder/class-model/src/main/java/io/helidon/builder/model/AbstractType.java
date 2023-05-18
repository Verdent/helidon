package io.helidon.builder.model;

import java.util.Objects;

import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNameDefault;

abstract class AbstractType extends Type {

    private final TypeName typeName;

    AbstractType(Builder<?, ?> builder) {
        super(builder);
        this.typeName = builder.typeName;
    }

    String typeName() {
        return typeName.name();
    }

    String simpleTypeName() {
        return typeName.className();
    }

    boolean isArray() {
        return typeName.array();
    }

    String packageName() {
        return typeName.packageName();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AbstractType that = (AbstractType) o;
        return isArray() == that.isArray()
                && Objects.equals(typeName(), that.typeName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(isArray(), typeName());
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        if (includeImport()) {
            imports.addImport(this);
        }
    }

    static abstract class Builder<B extends Builder<B, T>, T extends AbstractType> extends ModelComponent.Builder<B, T> {
        private TypeName typeName;

        Builder() {
        }

        public B type(String type) {
            return type(TypeNameDefault.createFromTypeName(type));
        }

        public B type(Class<?> type) {
            return type(TypeNameDefault.create(type));
        }

        public B type(TypeName typeName) {
            this.typeName = typeName;
            return identity();
        }

        TypeName typeName() {
            return typeName;
        }
    }

}
