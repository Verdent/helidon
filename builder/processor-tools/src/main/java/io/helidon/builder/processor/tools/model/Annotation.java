package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * TODO javadoc
 */
public class Annotation extends AbstractComponent {

    private final Map<String, AnnotParameter> parameters;

    private Annotation(Builder builder) {
        super(builder);
        this.parameters = new LinkedHashMap<>(builder.parameters);
    }

    public static Builder builder(String type) {
        return new Builder(type);
    }

    public static Builder builder(Class<? extends java.lang.annotation.Annotation> type) {
        return new Builder(type);
    }

    public static Annotation create(String type) {
        return builder(type).build();
    }

    public static Annotation create(Class<? extends java.lang.annotation.Annotation> type) {
        return builder(type).build();
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.write("@" + imports.typeName(type(), includeImport()));
        if (!parameters.isEmpty()) {
            writer.write("(");
            if (parameters.size() == 1) {
                for (AnnotParameter parameter : parameters.values()) {
                    if (parameter.name().equals("value")) {
                        writer.write(parameter.value());
                    } else {
                        parameter.writeComponent(writer, declaredTokens, imports);
                    }
                }
            } else {
                boolean first = true;
                for (AnnotParameter parameter : parameters.values()) {
                    if (first) {
                        first = false;
                    } else {
                        writer.write(", ");
                    }
                    parameter.writeComponent(writer, declaredTokens, imports);
                }
            }
            writer.write(")");
        }
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        parameters.values().forEach(parameter -> parameter.addImports(imports));
    }

    public static class Builder extends AbstractComponent.Builder<Annotation, Builder> {

        private final Map<String, AnnotParameter> parameters = new LinkedHashMap<>();

        private Builder(Class<? extends java.lang.annotation.Annotation> type) {
            this(type.getName());
        }

        private Builder(String type) {
            super(null, Type.exact(type));
        }

        @Override
        public Annotation build() {
            return new Annotation(this);
        }

        public Builder addParameter(AnnotParameter parameter) {
            parameters.put(parameter.name(), parameter);
            return this;
        }

    }


}
