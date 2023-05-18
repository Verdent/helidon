package io.helidon.builder.model;

import java.util.Objects;

import io.helidon.common.types.TypeName;

abstract class CommonComponent extends ModelComponent {

    private final String name;
    private final Type type;
    private final Javadoc javadoc;
    private final AccessModifier accessModifier;

    CommonComponent(Builder<?, ?> builder) {
        super(builder);
        this.name = builder.name;
        this.type = builder.type;
        this.accessModifier = builder.accessModifier;
        this.javadoc = builder.javadocBuilder.build();
    }

    @Override
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

    Javadoc javadoc() {
        return javadoc;
    }

    AccessModifier accessModifier() {
        return accessModifier;
    }

    abstract static class Builder<B extends Builder<B, T>, T extends CommonComponent> extends ModelComponent.Builder<B, T> {
        private final Javadoc.Builder javadocBuilder = Javadoc.builder();
        private AccessModifier accessModifier = AccessModifier.PUBLIC;
        private String name;
        private Type type;

        Builder() {
        }

        B type(TypeName type) {
            return type(Type.fromTypeName(type));
        }

        B type(String type) {
            return type(Type.exact(type));
        }

        B type(Class<?> type) {
            return type(Type.exact(type));
        }

        B type(Type type) {
            this.type = type;
            return identity();
        }

        public B description(String description) {
            this.javadocBuilder.add(description);
            this.javadocBuilder.generate(true);
            return identity();
        }


        /**
         * Set whether to generate javadoc or not.
         * Javadoc is automatically generated when description is set.
         *
         * @param generateJavadoc true if javadoc should be generated
         * @return updated builder instance
         */
        B generateJavadoc(boolean generateJavadoc) {
            this.javadocBuilder.generate(generateJavadoc);
            return identity();
        }

        B addJavadocParameter(String param, String description) {
            this.javadocBuilder.addParameter(param, description);
            return identity();
        }

        B addGenericToken(String token, String description) {
            this.javadocBuilder.addGenericsToken(token, description);
            return identity();
        }

        B addJavadocThrows(String exception, String description) {
            this.javadocBuilder.addThrows(exception, description);
            return identity();
        }

        B deprecationJavadoc(String description) {
            this.javadocBuilder.deprecation(description);
            return identity();
        }

        B returnJavadoc(String description) {
            this.javadocBuilder.returnDescription(description);
            return identity();
        }

        B tokenJavadoc(String token, String description) {
            this.javadocBuilder.addGenericsToken(token, description);
            return identity();
        }

        B name(String name) {
            this.name = Objects.requireNonNull(name);
            return identity();
        }

        B accessModifier(AccessModifier accessModifier) {
            this.accessModifier = Objects.requireNonNull(accessModifier);
            return identity();
        }

        String name() {
            return name;
        }

        Type type() {
            return type;
        }
    }

}
