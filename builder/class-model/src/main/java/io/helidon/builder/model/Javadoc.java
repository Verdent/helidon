package io.helidon.builder.model;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

class Javadoc extends ModelComponent {

    private final String content;
    private final Set<String> authors;
    private final Map<String, String> parameters;
    private final Map<String, String> genericsTokens;
    private final Map<String, String> throwsDesc;
    private final String returnDescription;
    private final String deprecation;
    private final Boolean generate;

    private Javadoc(Builder builder) {
        super(builder);
        this.content = builder.contentBuilder.toString();
        this.authors = new LinkedHashSet<>(builder.authors);
        this.parameters = new LinkedHashMap<>(builder.parameters);
        this.genericsTokens = new LinkedHashMap<>(builder.genericsTokens);
        this.throwsDesc = new LinkedHashMap<>(builder.throwsDesc);
        this.returnDescription = builder.returnDescription;
        this.deprecation = builder.deprecation;
        this.generate = builder.generate;
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
        for (String author : authors) {
            writer.write(" * @author " + author + "\n");
        }
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            writer.write(" * @param " + entry.getKey() + " " + entry.getValue() + "\n");
        }
        for (Map.Entry<String, String> entry : genericsTokens.entrySet()) {
            writer.write(" * @param <" + entry.getKey() + "> " + entry.getValue() + "\n");
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
        writer.write(" */");
    }

    boolean generate() {
//        if (generate != null) {
//            return generate;
//        }
//        return switch (accessModifier) {
//            case PUBLIC, PROTECTED -> true;
//            default -> false;
//        };
        return generate;
    }

    private boolean hasAnyOtherParts() {
        return !parameters.isEmpty()
                || !throwsDesc.isEmpty()
                || !genericsTokens.isEmpty()
                || !authors.isEmpty()
                || returnDescription != null
                || deprecation != null;
    }

    public static final class Builder extends ModelComponent.Builder<Builder, Javadoc> {

        private final StringBuilder contentBuilder = new StringBuilder();
        private final Set<String> authors = new LinkedHashSet<>();
        private final Map<String, String> parameters = new LinkedHashMap<>();
        private final Map<String, String> genericsTokens = new LinkedHashMap<>();
        private final Map<String, String> throwsDesc = new LinkedHashMap<>();
        private String returnDescription;
        private String deprecation;
        private Boolean generate = false;

        private Builder() {
        }

        @Override
        public Javadoc build() {
            return new Javadoc(this);
        }

        Builder addLine(String line) {
            this.contentBuilder.append(line).append("\n");
            return this;
        }

        Builder add(String line) {
            this.contentBuilder.append(line);
            return this;
        }

        Builder addAuthor(String author) {
            this.authors.add(author);
            return this;
        }

        Builder addParameter(String paramName, String description) {
            this.parameters.put(paramName, description);
            return this;
        }

        Builder addThrows(String exception, String description) {
            this.throwsDesc.put(exception, description);
            return this;
        }
        Builder addThrows(Class<?> exception, String description) {
            this.throwsDesc.put(exception.getSimpleName(), description);
            return this;
        }

        Builder returnDescription(String returnDescription) {
            this.returnDescription = returnDescription;
            return this;
        }

        Builder addGenericsToken(String token, String deprecation) {
            this.genericsTokens.put(token, deprecation);
            return this;
        }

        Builder deprecation(String deprecation) {
            this.deprecation = deprecation;
            return this;
        }

        Builder generate(boolean generate) {
            this.generate = generate;
            return this;
        }

    }
}
