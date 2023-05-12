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
    private final Javadoc javadoc;

    AbstractComponent(Builder<?, ?> builder) {
        this.name = builder.name;
        this.type = builder.type;
        this.includeImport = builder.includeImport;
        this.javadoc = builder.javadocBuilder.build();
    }

    abstract void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException;

    void addImports(ImportOrganizer.Builder imports) {
        if (includeImport() && type != null) {
            imports.addImport(type);
        }
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

    Javadoc javadoc() {
        return javadoc;
    }

    static abstract class Builder<T extends AbstractComponent, B extends Builder<T, B>> {

        private final Javadoc.Builder javadocBuilder = Javadoc.builder();
        private final B me;
        private final String name;
        private final Type type;
        private boolean includeImport = true;

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

        public B description(String description) {
            this.javadocBuilder.add(description);
            return me;
        }

        /**
         * Set whether to generate javadoc or not.
         * Javadoc is automatically generated for public and protected methods, but disabled
         * for private and package private ones.
         *
         * @param generateJavadoc true if javadoc should be generated
         * @return updated builder instance
         */
        B generateJavadoc(boolean generateJavadoc) {
            this.javadocBuilder.generate(generateJavadoc);
            return me;
        }

        B addJavadocParameter(String param, String description) {
            this.javadocBuilder.addParameter(param, description);
            return me;
        }

        B addJavadocThrows(String exception, String description) {
            this.javadocBuilder.addThrows(exception, description);
            return me;
        }

        B deprecationJavadoc(String description) {
            this.javadocBuilder.deprecation(description);
            return me;
        }

        B returnJavadoc(String description) {
            this.javadocBuilder.returnDescription(description);
            return me;
        }

        B tokenJavadoc(String token, String description) {
            this.javadocBuilder.addGenericsToken(token, description);
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
