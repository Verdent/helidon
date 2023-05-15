package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

public final class Token extends Type {

    private final String token;
    private final Type bound;
    private final String description;

    private Token(Builder builder) {
        this.token = builder.token;
        this.bound = builder.bound;
        this.description = builder.description;
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.write(token);
        if (bound != null) {
            writer.write(" extends ");
            bound.writeComponent(writer, declaredTokens, imports);
        }
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        if (bound != null) {
            bound.addImports(imports);
        }
    }

    String token() {
        return token;
    }

    String description() {
        return description;
    }

    @Override
    String typeName() {
        return token;
    }

    @Override
    String simpleTypeName() {
        return token;
    }

    @Override
    boolean isInnerType() {
        return false;
    }

    @Override
    boolean isArray() {
        return false;
    }

    @Override
    String type() {
        return token;
    }

    @Override
    String outerClass() {
        return null;
    }

    @Override
    String packageName() {
        return "";
    }

    @Override
    public String toString() {
        return "Token: " + token;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Token token1 = (Token) o;
        return Objects.equals(token, token1.token)
                && Objects.equals(bound, token1.bound);
    }

    @Override
    public int hashCode() {
        return Objects.hash(token, bound);
    }

    public static class Builder {

        private final String token;
        private Type bound;
        private String description = "";

        Builder(String token) {
            this.token = token;
        }

        public Builder bound(String bound) {
            return bound(Type.exact(bound));
        }

        public Builder bound(Class<?> bound) {
            return bound(Type.exact(bound));
        }

        public Builder bound(Type bound) {
            this.bound = bound;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Token build() {
            return new Token(this);
        }

    }
}
