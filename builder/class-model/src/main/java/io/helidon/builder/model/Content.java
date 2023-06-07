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

public class Content {

    private final StringBuilder content;
    private final Set<String> toImport;
    private final Map<String, List<Position>> tokenPositions;

    private Content(Builder builder) {
        this.content = new StringBuilder(builder.content);
        this.toImport = Set.copyOf(builder.toImport);
        this.tokenPositions = Map.copyOf(builder.tokenPositions);
    }

    static Builder builder() {
        return new Builder();
    }

    void writeBody(ModelWriter writer, ImportOrganizer imports, boolean increasePadding) throws IOException {
        tokenPositions.forEach((className, positions) -> {
            TypeName typeName = TypeNameDefault.createFromTypeName(className);
            String replacement = imports.typeName(Type.fromTypeName(typeName));
            positions.forEach(position -> {
                content.replace(position.start, position.end, replacement);
            });
        });
        if (increasePadding) {
            writer.increasePaddingLevel();
        }
        String[] lines = content.toString().split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            writer.write(line);
            if (i + 1 == lines.length && increasePadding) {
                writer.decreasePaddingLevel();
            }
            writer.write("\n");
        }
    }

    void addImports(ImportOrganizer.Builder builder) {
        toImport.forEach(builder::addImport);
    }

    public static final class Builder implements io.helidon.common.Builder<Builder, Content> {

        private static final Pattern CLASS_NAME_PATTERN = Pattern.compile(CLASS_TOKEN_START + "(.*?)" + CLASS_TOKEN_END);

        private final StringBuilder content = new StringBuilder();
        private final Set<String> toImport = new HashSet<>();
        private final Map<String, List<Position>> tokenPositions = new HashMap<>();
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

        public Builder addLine(String line) {
            return add(line + "\n");
        }

        public Builder add(String line) {
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

        private void identifyClassTokens() {
            Matcher matcher = CLASS_NAME_PATTERN.matcher(content);
            while (matcher.find()) {
                String className = matcher.group(1);
                toImport.add(className);
                tokenPositions.computeIfAbsent(className, key -> new ArrayList<>())
                        .add(new Position(matcher.start(), matcher.end()));
            }
        }

        public Builder increasePadding() {
            this.extraPaddingLevel++;
            this.extraPadding = PADDING_TOKEN.repeat(this.extraPaddingLevel);
            return this;
        }

        public Builder decreasePadding() {
            this.extraPaddingLevel--;
            if (this.extraPaddingLevel < 0) {
                throw new ClassModelException("Content padding cannot be negative");
            }
            this.extraPadding = PADDING_TOKEN.repeat(this.extraPaddingLevel);
            return this;
        }
    }

    private record Position(int start, int end) {
    }


}
