package io.helidon.builder.processor.tools.model.newModel;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * TODO javadoc
 */
public class Method extends AbstractMethod implements Comparable<Method> {

    private final Map<String, Token> declaredTokens;
    private final boolean isFinal;
    private final boolean isStatic;
    private final boolean isAbstract;

    private Method(Builder builder) {
        super(builder);
        this.isFinal = builder.isFinal;
        this.isStatic = builder.isStatic;
        this.isAbstract = builder.isAbstract;
        this.declaredTokens = Map.copyOf(builder.declaredTokens);
    }

    public static Builder builder() {
        return new Builder().type(void.class);
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        if (javadoc().generate()) {
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
        type().writeComponent(writer, declaredTokens, imports); //write return type
        writer.write(" " + name() + "(");
        boolean first = true;
        for (Parameter parameter : parameters()) {
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
            tokensToDeclare = parameters().stream()
                    .filter(parameter -> parameter.type() instanceof Token)
                    .map(parameter -> ((Token) parameter.type()).token())
                    .filter(tokenName -> !tokenName.equals("?"))
                    .collect(Collectors.toSet());
        } else {
            tokensToDeclare = parameters().stream()
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
        type().addImports(imports);
    }

    boolean isStatic() {
        return isStatic;
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
        return Objects.equals(type(), method.type())
                && Objects.equals(name(), method.name())
                && parameters().size() == method.parameters().size()
                && parameters().containsAll(method.parameters());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type(), name(), parameters());
    }

    @Override
    public int compareTo(Method other) {
        if (accessModifier() == other.accessModifier()) {
            return name().compareTo(other.name());
        } else {
            return accessModifier().compareTo(other.accessModifier());
        }
    }

    @Override
    public String toString() {
        return "Method{" +
                "name=" + name() +
                ", isFinal=" + isFinal +
                ", isStatic=" + isStatic +
                ", isAbstract=" + isAbstract +
                ", returnType=" + type().typeName() +
                '}';
    }

    public static class Builder extends AbstractMethod.Builder<Builder, Method> {

        private final Map<String, Token> declaredTokens = new HashMap<>();
        private boolean isFinal = false;
        private boolean isStatic = false;
        private boolean isAbstract = false;

        Builder() {
        }

        public Method build() {
            if (name() != null) {
                throw new ClassModelException("Method needs to have name specified");
            }
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
            return returnType(Type.exact(type), description);
        }

        public Builder returnType(Class<?> type) {
            return returnType(Type.exact(type));
        }

        public Builder returnType(Class<?> type, String description) {
            return returnType(Type.exact(type), description);
        }

        public Builder returnType(Type type) {
            return returnType(type, "");
        }

        public Builder returnType(Type type, String description) {
            return type(type).returnJavadoc(description);
        }

        public Builder addTokenDeclaration(Token token) {
            declaredTokens.put(token.token(), token);
            tokenJavadoc(token.token(), token.description());
            return this;
        }
    }

}
