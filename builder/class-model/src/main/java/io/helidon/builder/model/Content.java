package io.helidon.builder.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNameDefault;

import static io.helidon.builder.model.ClassModel.CLASS_TOKEN_END;
import static io.helidon.builder.model.ClassModel.CLASS_TOKEN_START;
import static io.helidon.builder.model.ClassModel.PADDING_TOKEN;

class Content {

    private final StringBuilder content;
    private final Set<String> toImport;
    private final List<Position> tokenPositions;

    private Content(Builder builder) {
        this.content = new StringBuilder(builder.content);
        this.toImport = Set.copyOf(builder.toImport);
        this.tokenPositions = List.copyOf(builder.tokenPositions);
    }

    static Builder builder() {
        return new Builder();
    }

    boolean hasBody() {
        return !content.isEmpty();
    }

    void writeBody(ModelWriter writer, ImportOrganizer imports, boolean decreaseAfterBody) throws IOException {
        int offset = 0;
        Map<String, String> replacements = new HashMap<>();
        for (Position position : tokenPositions) {
            String replacement = replacements.computeIfAbsent(position.type, key -> {
                TypeName typeName = TypeNameDefault.createFromTypeName(key);
                return imports.typeName(Type.fromTypeName(typeName));
            });
            content.replace(position.start - offset, position.end - offset, replacement);
            //Since we are replacing values in the StringBuilder, previously obtained position indexes for class name tokens
            //will differ and because fo that, these changes need to be reflected via calculating overall offset
            offset += (position.end - position.start) - replacement.length();
        }
        String[] lines = content.toString().split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            writer.write(line);
            if (i + 1 == lines.length && decreaseAfterBody) {
                writer.decreasePaddingLevel();
            }
            writer.write("\n");
        }
    }

    void addImports(ImportOrganizer.Builder builder) {
        toImport.forEach(builder::addImport);
    }

    static final class Builder implements io.helidon.common.Builder<Builder, Content> {

        private static final Pattern CLASS_NAME_PATTERN = Pattern.compile(CLASS_TOKEN_START + "(.*?)" + CLASS_TOKEN_END);

        private final StringBuilder content = new StringBuilder();
        private final Set<String> toImport = new HashSet<>();
        private final List<Position> tokenPositions = new ArrayList<>();
        private String extraPadding = "";
        private int extraPaddingLevel = 0;
        private boolean newLine = false;

        private Builder() {
        }

        @Override
        public Content build() {
            toImport.clear();
            tokenPositions.clear();
            identifyClassTokens();
            return new Content(this);
        }

        Builder content(String content) {
            this.content.setLength(0);
            this.content.append(content);
            return identity();
        }

        Builder addLine(String line) {
            return add(line + "\n");
        }

        Builder add(String line) {
            String trimmed = line.trim();
            if (trimmed.equals("}")) {
                decreasePadding();
            }
            if (newLine) {
                this.content.append(extraPadding);
                this.newLine = false;
            }
            this.content.append(line);
            this.newLine = line.endsWith("\n");
            if (trimmed.endsWith("{")) {
                increasePadding();
            }
            return this;
        }

        Builder className(String fqClassName) {
            return add(ClassModel.CLASS_TOKEN.replace("name", fqClassName));
        }

        Builder padding() {
            this.content.append(PADDING_TOKEN);
            return this;
        }

        Builder padding(int repetition) {
            this.content.append(PADDING_TOKEN.repeat(repetition));
            return this;
        }

        Builder increasePadding() {
            this.extraPaddingLevel++;
            this.extraPadding = PADDING_TOKEN.repeat(this.extraPaddingLevel);
            return this;
        }

        Builder decreasePadding() {
            this.extraPaddingLevel--;
            if (this.extraPaddingLevel < 0) {
                throw new ClassModelException("Content padding cannot be negative");
            }
            this.extraPadding = PADDING_TOKEN.repeat(this.extraPaddingLevel);
            return this;
        }

        private void identifyClassTokens() {
            Matcher matcher = CLASS_NAME_PATTERN.matcher(content);
            while (matcher.find()) {
                String className = matcher.group(1);
                toImport.add(className);
                tokenPositions.add(new Position(matcher.start(), matcher.end(), className));
            }
        }
    }

    private record Position(int start, int end, String type) {
    }


}
