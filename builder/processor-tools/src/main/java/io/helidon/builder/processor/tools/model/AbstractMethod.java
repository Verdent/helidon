package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * TODO javadoc
 */
abstract class AbstractMethod extends AbstractAnnotatable {

    private final String content;
    private final Map<String, Parameter> parameters;
    private final AccessModifier accessModifier;

    AbstractMethod(Builder<?, ?> builder) {
        super(builder);
        this.content = builder.contentBuilder.toString();
        this.accessModifier = builder.accessModifier;
        this.parameters = new LinkedHashMap<>(builder.parameters);
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        parameters.values().forEach(parameter -> parameter.addImports(imports));
    }

    void writeBody(ModelWriter writer) throws IOException {
        writer.increasePaddingLevel();
        writer.write("\n");
        String[] lines = content().split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            writer.write(line);
            if (i + 1 == lines.length) {
                writer.decreasePaddingLevel();
            }
            writer.write("\n");
        }
    }

    Map<String, Parameter> parameters() {
        return parameters;
    }

    String content() {
        return content;
    }

    AccessModifier accessModifier() {
        return accessModifier;
    }

    static abstract class Builder<T extends AbstractMethod, B extends Builder<T, B>>
            extends AbstractAnnotatable.Builder<T, B> {

        private final Map<String, Parameter> parameters = new LinkedHashMap<>();
        private final Set<String> exceptions = new LinkedHashSet<>();
        private final StringBuilder contentBuilder = new StringBuilder();
        private AccessModifier accessModifier = AccessModifier.PUBLIC;

        Builder(String name, Type returnType) {
            super(name, returnType);
        }

        public B accessModifier(AccessModifier accessModifier) {
            this.accessModifier = accessModifier;
            return identity();
        }

        public B addLine(String line) {
            this.contentBuilder.append(line).append("\n");
            return identity();
        }
        public B add(String line) {
            this.contentBuilder.append(line);
            return identity();
        }

        public B padding() {
            this.contentBuilder.append(ModelWriter.PADDING_TOKEN);
            return identity();
        }

        public B content(String content) {
            this.contentBuilder.setLength(0);
            this.contentBuilder.append(content);
            return identity();
        }

        public B addParameter(Parameter parameter) {
            this.parameters.put(parameter.name(), parameter);
            return this.addJavadocParameter(parameter.name(), parameter.description());
        }

        public B addParameter(Parameter.Builder builder) {
            Parameter parameter = builder.build();
            this.parameters.put(parameter.name(), parameter);
            return this.addJavadocParameter(parameter.name(), parameter.description());
        }

        public B addThrows(String exception) {
            return addThrows(exception, "");
        }

        public B addThrows(Class<?> exception) {
            return addThrows(exception, "");
        }

        public B addThrows(String exception, String description) {
            this.exceptions.add(exception);
            return addJavadocThrows(exception, description);
        }

        public B addThrows(Class<?> exception, String description) {
            return addThrows(exception.getName(), description);
        }

        @Override
        public B generateJavadoc(boolean generateJavadoc) {
            return super.generateJavadoc(generateJavadoc);
        }
    }

}
