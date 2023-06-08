package io.helidon.builder.model;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNameDefault;

import static io.helidon.builder.model.ClassModel.CLASS_TOKEN_END;
import static io.helidon.builder.model.ClassModel.CLASS_TOKEN_START;

abstract class AbstractMethod extends AnnotatableComponent {

    private static final Pattern CLASS_NAME_PATTERN = Pattern.compile(CLASS_TOKEN_START + "(.*?)" + CLASS_TOKEN_END);

    private final Content content;
    private final List<Parameter> parameters;

    AbstractMethod(Builder<?, ?> builder) {
        super(builder);
        this.content = builder.contentBuilder.build();
        this.parameters = List.copyOf(builder.parameters.values());
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        parameters.forEach(parameter -> parameter.addImports(imports));
        content.addImports(imports);
    }

    void writeBody(ModelWriter writer, ImportOrganizer imports) throws IOException {
        writer.increasePaddingLevel();
        writer.write("\n");
        content.writeBody(writer, imports);
        writer.decreasePaddingLevel();
        writer.write("\n");
    }

    List<Parameter> parameters() {
        return parameters;
    }

    boolean hasBody() {
        return content.hasBody();
    }

    static abstract class Builder<B extends Builder<B, T>, T extends AbstractMethod>
            extends AnnotatableComponent.Builder<B, T> {

        private final Map<String, Parameter> parameters = new LinkedHashMap<>();
        private final Set<String> exceptions = new LinkedHashSet<>();
        private final Content.Builder contentBuilder = Content.builder();

        Builder() {
        }

        @Override
        public B accessModifier(AccessModifier accessModifier) {
            return super.accessModifier(accessModifier);
        }

        public B addLine(String line) {
            return add(line + "\n");
        }

        public B add(String line) {
            contentBuilder.add(line);
            return identity();
        }

        public B className(String fqClassName) {
            contentBuilder.className(fqClassName);
            return identity();
        }

        public B padding() {
            contentBuilder.padding();
            return identity();
        }

        public B padding(int repetition) {
            contentBuilder.padding(repetition);
            return identity();
        }

        public B increasePadding() {
            contentBuilder.increasePadding();
            return identity();
        }

        public B decreasePadding() {
            contentBuilder.decreasePadding();
            return identity();
        }

        public B content(String content) {
            contentBuilder.content(content);
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

