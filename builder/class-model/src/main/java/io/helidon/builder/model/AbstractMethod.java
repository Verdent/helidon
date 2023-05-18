package io.helidon.builder.model;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import static io.helidon.builder.model.ClassModel.PADDING_TOKEN;

abstract class AbstractMethod extends AnnotatableComponent {

    private final String content;
    private final List<Parameter> parameters;

    AbstractMethod(Builder<?, ?> builder) {
        super(builder);
        this.content = builder.contentBuilder.toString();
        this.parameters = List.copyOf(builder.parameters.values());
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        parameters.forEach(parameter -> parameter.addImports(imports));
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

    List<Parameter> parameters() {
        return parameters;
    }

    String content() {
        return content;
    }

    static abstract class Builder<B extends Builder<B, T>, T extends AbstractMethod>
            extends AnnotatableComponent.Builder<B, T> {

        private final Map<String, Parameter> parameters = new LinkedHashMap<>();
        private final Set<String> exceptions = new LinkedHashSet<>();
        private final StringBuilder contentBuilder = new StringBuilder();

        Builder() {
        }

        @Override
        public B accessModifier(AccessModifier accessModifier) {
            return super.accessModifier(accessModifier);
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
            this.contentBuilder.append(PADDING_TOKEN);
            return identity();
        }

        public B content(String content) {
            this.contentBuilder.setLength(0);
            this.contentBuilder.append(content);
            return identity();
        }

        public B addParameter(Consumer<Parameter.Builder> consumer) {
            Parameter.Builder builder = Parameter.builder();
            consumer.accept(builder);
            return addParameter(builder.build());
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

