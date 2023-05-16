package io.helidon.builder.processor.tools.model.newModel;

import java.io.IOException;
import java.util.Set;

abstract class ModelComponent {

    ModelComponent(Builder<?, ?> builder) {
    }

    abstract void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException;

    void addImports(ImportOrganizer.Builder imports) {

    }

    public static abstract class Builder<B extends Builder<B, T>, T extends ModelComponent>
            implements io.helidon.common.Builder<B, T> {

        Builder() {
        }

    }

}
