package io.helidon.builder.processor.tools.model;

import java.util.Objects;

abstract class AbstractType extends Type{

    private final boolean includeImport;
    private final boolean isInnerType;
    private final boolean isArray;
    private final String type;
    private final String outerClass;
    private final String packageName;
    private final String simpleTypeName;

    AbstractType(Builder<?> builder) {
        this.includeImport = builder.includeImport;
        this.isInnerType = builder.isInnerType;
        this.type = builder.type;
        this.outerClass = builder.outerClass;
        this.packageName = builder.packageName;
        this.simpleTypeName = builder.simpleTypeName;
        this.isArray = builder.isArray;
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        if (includeImport) {
            imports.addImport(this);
        }
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

    boolean includeImport() {
        return includeImport;
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

    static abstract class Builder<B extends Builder<B>> {
        private String type;
        private String simpleTypeName;
        private String outerClass;
        private String packageName = "";
        private boolean includeImport = true;
        private boolean isInnerType = false;
        private boolean isArray = false;
        private final B me;

        Builder(String type) {
            this.type = type;
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

        public abstract Type build();

        public B includeImport(boolean includeImport) {
            this.includeImport = includeImport;
            return me;
        }

    }

}
