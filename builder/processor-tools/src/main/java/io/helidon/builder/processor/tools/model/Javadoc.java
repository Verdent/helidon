package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class Javadoc {

    private final String content;
    private final Map<String, String> parameters;
    private final Map<String, String> throwsDesc;
    private final String returnDescription;
    private final String deprecation;

    private Javadoc(Builder builder) {
        this.content = builder.contentBuilder.toString();
        this.parameters = new LinkedHashMap<>(builder.parameters);
        this.throwsDesc = new LinkedHashMap<>(builder.throwsDesc);
        this.returnDescription = builder.returnDescription;
        this.deprecation = builder.deprecation;
    }

    public static Javadoc create(String content) {
        return builder().add(content).build();
    }

    public static Builder builder() {
        return new Builder();
    }

    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.write("/**\n");
        String[] lines = content.split("\n");
        for (String line : lines) {
            writer.write(" * " + line + "\n");
        }
        if (hasAnyOtherParts()) {
            writer.write(" * \n");
        }
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            writer.write(" * @param " + entry.getKey() + " " + entry.getValue() + "\n");
        }
        if (returnDescription != null) {
            writer.write(" * @return " + returnDescription + "\n");
        }
        if (deprecation != null) {
            writer.write(" * @deprecation " + deprecation + "\n");
        }
        for (Map.Entry<String, String> entry : throwsDesc.entrySet()) {
            writer.write(" * @throws " + entry.getKey() + " " + entry.getValue() + "\n");
        }
        writer.write(" **/");
    }

    private boolean hasAnyOtherParts() {
        return parameters.size() > 0
                || throwsDesc.size() > 0
                || returnDescription != null
                || deprecation != null;
    }

    public static final class Builder {

        private final StringBuilder contentBuilder = new StringBuilder();
        private final Map<String, String> parameters = new LinkedHashMap<>();
        private final Map<String, String> throwsDesc = new LinkedHashMap<>();
        private String returnDescription;
        private String deprecation;

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

        public Builder addParameter(String paramName, String description) {
            this.parameters.put(paramName, description);
            return this;
        }

        public Builder addThrows(String exception, String description) {
            this.throwsDesc.put(exception, description);
            return this;
        }
        public Builder addThrows(Class<?> exception, String description) {
            this.throwsDesc.put(exception.getSimpleName(), description);
            return this;
        }

        public Builder returnDescription(String returnDescription) {
            this.returnDescription = returnDescription;
            return this;
        }

        public Builder deprecation(String deprecation) {
            this.deprecation = deprecation;
            return this;
        }

    }
}
