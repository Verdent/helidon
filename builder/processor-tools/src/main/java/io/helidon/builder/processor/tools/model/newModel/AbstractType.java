package io.helidon.builder.processor.tools.model.newModel;

import java.util.Objects;

abstract class AbstractType extends Type {

    private final boolean isInnerType;
    private final boolean isArray;
    private final String type;
    private final String outerClass;
    private final String packageName;
    private final String simpleTypeName;

    AbstractType(Builder<?, ?> builder) {
        super(builder);
        this.isInnerType = builder.isInnerType;
        this.type = builder.type;
        this.outerClass = builder.outerClass;
        this.packageName = builder.packageName;
        this.simpleTypeName = builder.simpleTypeName;
        this.isArray = builder.isArray;
    }

    String typeName() {
        return type;
    }

    String simpleTypeName() {
        return simpleTypeName;
    }

    boolean isInnerType() {
        return isInnerType;
    }

    boolean isArray() {
        return isArray;
    }

    String type() {
        return type;
    }

    String outerClass() {
        return outerClass;
    }

    String packageName() {
        return packageName;
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
        return isArray == that.isArray
                && Objects.equals(type, that.type);
    }

    @Override
    public int hashCode() {
        return Objects.hash(isArray, type);
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        if (includeImport()) {
            imports.addImport(this);
        }
    }

    static abstract class Builder<B extends Builder<B, T>, T extends AbstractType> extends ModelComponent.Builder<B, T> {
        private String type;
        private String simpleTypeName;
        private String outerClass;
        private String packageName = "";
        private boolean includeImport = true;
        private boolean isInnerType = false;
        private boolean isArray = false;
        private final B me;

        Builder() {
            this.me = (B) this;
        }

        void commonBuildLogic() {
            if (type != null) {
                if (type.endsWith("[]")) {
                    isArray = true;
                    type = type.substring(0, type.length() - 2);
                }
                int lastIndexOf = type.lastIndexOf(".");
                if (lastIndexOf < 0) {
                    simpleTypeName = type;
                } else {
                    simpleTypeName = type.substring(lastIndexOf + 1);
                    packageName = type.substring(0, lastIndexOf);
                }
                if (simpleTypeName.contains("$")) {
                    type = type.replaceAll("\\$", ".");
                    int index = simpleTypeName.indexOf("$");
                    outerClass = simpleTypeName.substring(0, index);
                    simpleTypeName = simpleTypeName.substring(index +1);
                    isInnerType = true;
                }
            }
        }

        public B type(String type) {
            this.type = type;
            return me;
        }

        public abstract T build();

    }

}
