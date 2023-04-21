package io.helidon.builder.processor.tools.model;

import java.io.IOException;

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
    void writeComponent(ModelWriter writer, ImportOrganizer imports) throws IOException {
        for (Annotation annotation : annotations()) {
            annotation.writeComponent(writer, imports);
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
        type().writeComponent(writer, imports); //write return type
        writer.write(" " + name() + "(");
        boolean first = true;
        for (Parameter parameter : parameters().values()) {
            if (first) {
                first = false;
            } else {
                writer.write(", ");
            }
            parameter.writeComponent(writer, imports);
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
