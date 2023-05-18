package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

abstract class ModelComponent {

    private final boolean includeImport;

    ModelComponent(Builder<?, ?> builder) {
        this.includeImport = builder.includeImport;
    }

    abstract void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException;

    void addImports(ImportOrganizer.Builder imports) {
    }

    boolean includeImport() {
        return includeImport;
    }

    public static abstract class Builder<B extends Builder<B, T>, T extends ModelComponent>
            implements io.helidon.common.Builder<B, T> {

        private boolean includeImport = true;

        Builder() {
        }

        public B includeImport(boolean includeImport) {
            this.includeImport = includeImport;
            return identity();
        }

    }

}
