package io.helidon.builder.processor.tools.model;

abstract class AbstractType extends Type{

    private final boolean includeImport;
    private final boolean isInnerType;
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

    static abstract class Builder<B extends Builder<B>> {
        private String type;
        private String simpleTypeName;
        private String outerClass;
        private String packageName = "";
        private boolean includeImport = true;
        private boolean isInnerType = false;
        private final B me;

        Builder(String type) {
            this.type = type;
            this.me = (B) this;
        }

        void commonBuildLogic() {
            if (type != null) {
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
