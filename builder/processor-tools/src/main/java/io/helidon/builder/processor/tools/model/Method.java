package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * TODO javadoc
 */
public class Method extends AbstractMethod {

    private final boolean isFinal;
    private final boolean isStatic;
    private final boolean isAbstract;

    private Method(Builder builder) {
        super(builder);
        this.isFinal = builder.isFinal;
        this.isStatic = builder.isStatic;
        this.isAbstract = builder.isAbstract;
    }

    public static Builder builder(String name, Class<?> returnType) {
        return new Builder(name, Type.create(returnType));
    }

    public static Builder builder(String name, String returnType) {
        return new Builder(name, Type.create(returnType));
    }

    public static Builder builder(String name, Type returnType) {
        return new Builder(name, returnType);
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        if (javadoc() != null) {
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
        appendTokenDeclaration(writer, declaredTokens);
        type().writeComponent(writer, declaredTokens, imports); //write return type
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

    private void appendTokenDeclaration(ModelWriter writer, Set<String> declaredTokens) throws IOException {
        Set<String> tokensToDeclare = parameters().values()
                .stream()
                .filter(parameter -> parameter.type() instanceof Token)
                .map(parameter -> ((Token) parameter.type()).token())
                .filter(tokenName -> !declaredTokens.contains(tokenName))
                .filter(tokenName -> !tokenName.equals("?"))
                .collect(Collectors.toSet());
        if (!tokensToDeclare.isEmpty()) {
            writer.write("<");
            boolean first = true;
            for (String token : tokensToDeclare) {
                if (first) {
                    first = false;
                } else {
                    writer.write(", ");
                }
                writer.write(token);
            }
            writer.write("> ");
        }
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        type().addImports(imports);
    }

    public static class Builder extends AbstractMethod.Builder<Method, Builder> {

        private boolean isFinal = false;
        private boolean isStatic = false;
        private boolean isAbstract = false;

        Builder(String name, Type returnType) {
            super(name, returnType);
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
    }

}
