package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

/**
 * TODO javadoc
 */
public class AnnotParameter extends AbstractComponent {

    private final String value;

    public AnnotParameter(Builder builder) {
        super(builder);
        this.value = builder.resolvedValue;
    }

    public static <T> AnnotParameter create(String name, Class<T> type, T value) {
        return create(name, type.getName(), value);
    }

    public static AnnotParameter create(String name, String typeName, Object value) {
        return new Builder(name, typeName, value).build();
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.write(name() + " = " + value);
    }

    @Override
    public String toString() {
        return "AnnotParamer{type=" + type().typeName() + ", simpleType=" + type().simpleTypeName() + ", name=" + name() + "}";
    }

    String value() {
        return value;
    }

    public static class Builder extends AbstractComponent.Builder<AnnotParameter, Builder> {

        private final Object value;
        private String resolvedValue;

        private Builder(String name, String typeName, Object value) {
            super(name, Type.create(typeName));
            this.value = value;
        }

        public AnnotParameter build() {
            resolveProperType();
            return new AnnotParameter(this);
        }

        private void resolveProperType() {
            Class<?> valueClass = value.getClass();
            if (valueClass.isEnum()) {
                resolvedValue = valueClass.getSimpleName() + "." + ((Enum<?>) value).name();
                return;
            } else if (type().typeName().equals(String.class.getName())) {
                resolvedValue = "\"" + value + "\"";
                return;
            }
            resolvedValue = value.toString();
        }

    }
}
