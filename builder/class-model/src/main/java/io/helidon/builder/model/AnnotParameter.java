package io.helidon.builder.model;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

import io.helidon.common.types.TypeName;

class AnnotParameter extends CommonComponent {

    private final String value;

    AnnotParameter(Builder builder) {
        super(builder);
        this.value = resolveValueToString(builder.type(), builder.value);
    }

    static AnnotParameter create(String name, Type type, Object value) {
        return new Builder()
                .name(name)
                .type(type)
                .value(value)
                .build();
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.write(name() + " = " + value);
    }

    private static String resolveValueToString(Type type, Object value) {
        Class<?> valueClass = value.getClass();
        if (valueClass.isEnum()) {
            return valueClass.getSimpleName() + "." + ((Enum<?>) value).name();
        } else if (type.typeName().equals(String.class.getName())) {
            String stringValue = value.toString();
            if (!stringValue.startsWith("\"") && !stringValue.endsWith("\"")) {
                return "\"" + stringValue + "\"";
            }
        }
        return value.toString();
    }

    String value() {
        return value;
    }

    static final class Builder extends CommonComponent.Builder<Builder, AnnotParameter> {

        private Object value;

        private Builder() {
        }

        @Override
        public AnnotParameter build() {
            if (value == null || name() == null) {
                throw new ClassModelException("Annotation parameter needs to have value and type set");
            }
            return new AnnotParameter(this);
        }

        public Builder value(Object value) {
            this.value = Objects.requireNonNull(value);
            return this;
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

    }
}
