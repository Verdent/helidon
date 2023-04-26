package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

public class Javadoc {

    private final String content;

    private Javadoc(Builder builder) {
        this.content = builder.contentBuilder.toString();
    }

    public static Builder builder() {
        return new Builder();
    }

    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.write("/**\n");
        String[] lines = content.split("\n");
        for (String line : lines) {
            writer.write(" *" + line + "\n");
        }
        writer.write(" **/");
    }

    public static final class Builder {

        private final StringBuilder contentBuilder = new StringBuilder();

        private Builder() {
        }

        public Javadoc build() {
            return new Javadoc(this);
        }

        public Builder addLine(String line) {
            this.contentBuilder.append(line).append("\n");
            return this;
        }
        public Builder add(String line) {
            this.contentBuilder.append(line);
            return this;
        }

    }
}
