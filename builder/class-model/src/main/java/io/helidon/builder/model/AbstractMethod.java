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
import static io.helidon.builder.model.ClassModel.PADDING_TOKEN;

abstract class AbstractMethod extends AnnotatableComponent {

    private static final Pattern CLASS_NAME_PATTERN = Pattern.compile(CLASS_TOKEN_START + "(.*?)" + CLASS_TOKEN_END);

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
//        if (includeImport()) {
//            String[] lines = content().split("\n");
//            Matcher matcher = CLASS_NAME_PATTERN.matcher(line);
//        }
    }

    void writeBody(ModelWriter writer, ImportOrganizer imports) throws IOException {
        writer.increasePaddingLevel();
        writer.write("\n");
        String[] lines = content().split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = replaceClassTokens(lines[i], imports);
            writer.write(line);
            if (i + 1 == lines.length) {
                writer.decreasePaddingLevel();
            }
            writer.write("\n");
        }
    }

    private String replaceClassTokens(String line, ImportOrganizer imports) {
        Map<String, String> toReplace = new HashMap<>();
        StringBuilder builder = new StringBuilder();
        Matcher matcher = CLASS_NAME_PATTERN.matcher(line);
        int startIndex = 0;
        while (matcher.find()) {
            String replacement = toReplace.computeIfAbsent(matcher.group(1), key -> {
                TypeName typeName = TypeNameDefault.createFromTypeName(key);
                return imports.typeName(Type.fromTypeName(typeName));
            });
            builder.append(line, startIndex, matcher.start())
                    .append(replacement);
            startIndex = matcher.end();
        }
        if (builder.isEmpty()) {
            return line;
        }
        builder.append(line.substring(startIndex));
        return builder.toString();
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
        private String extraPadding = "";
        private int extraPaddingLevel = 0;
        private boolean newLine = false;

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
            if (newLine) {
                this.contentBuilder.append(extraPadding);
                this.newLine = false;
            }
            this.contentBuilder.append(line);
            this.newLine = line.endsWith("\n");
            return identity();
        }

        public B className(String fqClassName) {
            return add(ClassModel.CLASS_TOKEN.replace("name", fqClassName));
        }

        public B padding() {
            this.contentBuilder.append(PADDING_TOKEN);
            return identity();
        }

        public B padding(int repetition) {
            this.contentBuilder.append(PADDING_TOKEN.repeat(repetition));
            return identity();
        }

        public B increasePadding() {
            this.extraPaddingLevel++;
            this.extraPadding = PADDING_TOKEN.repeat(this.extraPaddingLevel);
            return identity();
        }

        public B decreasePadding() {
            this.extraPaddingLevel--;
            if (this.extraPaddingLevel < 0) {
                throw new ClassModelException("Content padding cannot be negative");
            }
            this.extraPadding = PADDING_TOKEN.repeat(this.extraPaddingLevel);
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

