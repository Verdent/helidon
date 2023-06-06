package io.helidon.builder.model;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import io.helidon.common.types.TypeName;

/**
 * TODO javadoc
 */
public class Annotation extends CommonComponent {

    private final List<AnnotParameter> parameters;

    private Annotation(Builder builder) {
        super(builder);
        this.parameters = List.copyOf(builder.parameters.values());
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Annotation create(Type type) {
        return builder().type(type).build();
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.write("@" + imports.typeName(type()));
        if (!parameters.isEmpty()) {
            writer.write("(");
            if (parameters.size() == 1) {
                AnnotParameter parameter = parameters.get(0);
                if (parameter.name().equals("value")) {
                    writer.write(parameter.value());
                } else {
                    parameter.writeComponent(writer, declaredTokens, imports);
                }
            } else {
                boolean first = true;
                for (AnnotParameter parameter : parameters) {
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
        parameters.forEach(parameter -> parameter.addImports(imports));
    }

    public static final class Builder extends CommonComponent.Builder<Builder, Annotation> {

        private final Map<String, AnnotParameter> parameters = new LinkedHashMap<>();

        private Builder() {
        }

        @Override
        public Annotation build() {
            if (type() == null) {
                throw new ClassModelException("Annotation type needs to be set");
            }
            return new Annotation(this);
        }


        @Override
        public Builder type(TypeName type) {
            return super.type(type);
        }

        @Override
        public Builder type(String type) {
            return super.type(type);
        }

        @Override
        public Builder type(Class<?> type) {
            return super.type(type);
        }

        @Override
        public Builder type(Type type) {
            return super.type(type);
        }

        /**
         * Adds annotation parameter.
         *
         * @param name annotation parameter name
         * @param value parameter value
         * @return updated builder instance
         */
        public Builder addParameter(String name, Object value) {
            Objects.requireNonNull(value);
            return addParameter(name, Type.exact(value.getClass()), value);
        }

        /**
         * Adds annotation parameter.
         *
         * @param name annotation parameter name
         * @param type parameter type to accurately handle passed value
         * @param value parameter value
         * @return updated builder instance
         */
        public Builder addParameter(String name, Type type, Object value) {
            Objects.requireNonNull(name);
            Objects.requireNonNull(type);
            Objects.requireNonNull(value);
            AnnotParameter parameter = AnnotParameter.create(name, type, value);
            parameters.put(parameter.name(), parameter);
            return this;
        }

    }


}
