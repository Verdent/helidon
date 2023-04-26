package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

/**
 * TODO javadoc
 */
abstract class AbstractComponent {

    private final String name;
    private final Type type;
    private final boolean includeImport;

    AbstractComponent(Builder<?, ?> builder) {
        this.name = builder.name;
        this.type = builder.type;
        this.includeImport = builder.includeImport;
    }

    abstract void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException;

    void addImports(ImportOrganizer.Builder imports) {
        if (includeImport()) {
            imports.addImport(type);
        }
    }

    void writeJavadoc(ModelWriter writer) {

    }

    String name() {
        return name;
    }

    Type type() {
        return type;
    }

    boolean includeImport() {
        return includeImport;
    }

    static abstract class Builder<T extends AbstractComponent, B extends Builder<T, B>> {
        private final String name;
        private final Type type;
        private boolean includeImport = true;
        private final B me;

        Builder(String name, Type type) {
            this.name = name;
            this.type = type;
            me = (B) this;
        }

        public abstract T build();

        public B includeImport(boolean includeImport) {
            this.includeImport = includeImport;
            return me;
        }

        B identity() {
            return me;
        }

        String name() {
            return name;
        }

        Type type() {
            return type;
        }

        boolean includeImport() {
            return includeImport;
        }
    }

}
