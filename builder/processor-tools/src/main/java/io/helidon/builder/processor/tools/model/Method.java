package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * TODO javadoc
 */
public class Method extends AbstractMethod {

    private final Map<String, Token> declaredTokens;
    private final boolean isFinal;
    private final boolean isStatic;
    private final boolean isAbstract;
    private final Type returnType;

    private Method(Builder builder) {
        super(builder);
        this.isFinal = builder.isFinal;
        this.isStatic = builder.isStatic;
        this.isAbstract = builder.isAbstract;
        this.returnType = builder.returnType;
        this.declaredTokens = Map.copyOf(builder.declaredTokens);
    }

    public static Builder builder(String name) {
        return new Builder(name);
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        if (javadoc().shouldGenerate(accessModifier())) {
            javadoc().writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        for (Annotation annotation : annotations()) {
            annotation.writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        if (AccessModifier.PACKAGE_PRIVATE != accessModifier()) {
            writer.write(accessModifier().modifierName() + " ");
        }
        if (isStatic) {
            if (isAbstract) {
                throw new IllegalStateException("Method cannot be static and abstract the same time");
            }
            writer.write("static ");
        }
        if (isFinal) {
            if (isAbstract) {
                throw new IllegalStateException("Method cannot be final and abstract the same time");
            }
            writer.write("final ");
        }
        if (isAbstract) {
            writer.write("abstract ");
        }
        appendTokenDeclaration(writer, declaredTokens, imports);
        returnType.writeComponent(writer, declaredTokens, imports); //write return type
        writer.write(" " + name() + "(");
        boolean first = true;
        for (Parameter parameter : parameters().values()) {
            if (first) {
                first = false;
            } else {
                writer.write(", ");
            }
            parameter.writeComponent(writer, declaredTokens, imports);
        }
        writer.write(")");
        if (isAbstract) {
            writer.write(";\n");
            return;
        }
        writer.write(" {");
        if (!content().isEmpty()) {
            writeBody(writer);
        } else {
            writer.write("\n");
        }
        writer.write("}");
    }

    private void appendTokenDeclaration(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports)
            throws IOException {
        Set<String> tokensToDeclare;
        if (isStatic) {
            tokensToDeclare = parameters().values()
                    .stream()
                    .filter(parameter -> parameter.type() instanceof Token)
                    .map(parameter -> ((Token) parameter.type()).token())
                    .filter(tokenName -> !tokenName.equals("?"))
                    .collect(Collectors.toSet());
        } else {
            tokensToDeclare = parameters().values()
                    .stream()
                    .filter(parameter -> parameter.type() instanceof Token)
                    .map(parameter -> ((Token) parameter.type()).token())
                    .filter(tokenName -> !declaredTokens.contains(tokenName))
                    .filter(tokenName -> !tokenName.equals("?"))
                    .collect(Collectors.toSet());
        }
        if (!tokensToDeclare.isEmpty()) {
            writer.write("<");
            boolean first = true;
            for (String token : tokensToDeclare) {
                if (first) {
                    first = false;
                } else {
                    writer.write(", ");
                }
                if (this.declaredTokens.containsKey(token)) {
                    this.declaredTokens.get(token).writeComponent(writer, declaredTokens, imports);
                } else {
                    writer.write(token);
                }
            }
            for (Map.Entry<String, Token> entry : this.declaredTokens.entrySet()) {
                if (!tokensToDeclare.contains(entry.getKey())) {
                    entry.getValue().writeComponent(writer, declaredTokens, imports);
                }
            }
            writer.write("> ");
        } else if (!this.declaredTokens.isEmpty()) {
            writer.write("<");
            boolean first = true;
            for (Map.Entry<String, Token> entry : this.declaredTokens.entrySet()) {
                if (first) {
                    first = false;
                } else {
                    writer.write(", ");
                }
                entry.getValue().writeComponent(writer, declaredTokens, imports);
            }
            writer.write("> ");
        }
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        if (includeImport()) {
            imports.addImport(returnType);
        }
        returnType.addImports(imports);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Method method = (Method) o;
        return Objects.equals(returnType, method.returnType)
                && Objects.equals(name(), method.name())
                && Objects.equals(parameters().values(), method.parameters().values());
    }

    @Override
    public int hashCode() {
        return Objects.hash(returnType);
    }

    public static class Builder extends AbstractMethod.Builder<Method, Builder> {

        private final Map<String, Token> declaredTokens = new HashMap<>();
        private boolean isFinal = false;
        private boolean isStatic = false;
        private boolean isAbstract = false;
        private Type returnType = Type.create(void.class);

        Builder(String name) {
            super(name, null);
        }

        public Method build() {
            return new Method(this);
        }

        public Builder isFinal(boolean isFinal) {
            this.isFinal = isFinal;
            return this;
        }

        public Builder isStatic(boolean isStatic) {
            this.isStatic = isStatic;
            return this;
        }

        public Builder isAbstract(boolean isAbstract) {
            this.isAbstract = isAbstract;
            return this;
        }

        public Builder returnType(String type) {
            return returnType(type, "");
        }

        public Builder returnType(String type, String description) {
            return returnType(Type.create(type), description);
        }

        public Builder returnType(Class<?> type) {
            return returnType(type.getName());
        }

        public Builder returnType(Class<?> type, String description) {
            return returnType(Type.create(type), description);
        }

        public Builder returnType(Type type) {
            return returnType(type, "");
        }

        public Builder returnType(Type type, String description) {
            this.returnType = type;
            return returnJavadoc(description);
        }

        public Builder addTokenDeclaration(Token token) {
            declaredTokens.put(token.token(), token);
            return this;
        }
    }

}
