package io.helidon.builder.processor.tools.model;

import java.io.IOException;

class Token extends Type {

    private final String token;
    private final Type bound;

    private Token(Builder builder) {
        this.token = builder.token;
        this.bound = builder.bound;
    }

    @Override
    void writeComponent(ModelWriter writer, ImportOrganizer imports) throws IOException {
        writer.write(token);
        if (bound != null) {
            writer.write(" extends ");
            bound.writeComponent(writer, imports);
        }
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        if (bound != null) {
            bound.addImports(imports);
        }
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

    static class Builder {

        private final String token;
        private final Type bound;

        Builder(String token) {
            this(token, null);
        }

        public Builder(String token, Type bound) {
            this.token = token;
            this.bound = bound;
        }

        public Token build() {
            return new Token(this);
        }

    }
}
