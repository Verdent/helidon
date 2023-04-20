package io.helidon.builder.processor.tools.model;

import java.util.ArrayList;
import java.util.List;

/**
 * TODO javadoc
 */
abstract class AbstractAnnotatable extends AbstractComponent {
    private final List<Annotation> annotations;
    AbstractAnnotatable(Builder<?, ?> builder) {
        super(builder);
        this.annotations = List.copyOf(builder.annotations);
    }

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        annotations().forEach(annotation -> annotation.addImports(imports));
    }

    List<Annotation> annotations() {
        return annotations;
    }

    static abstract class Builder<T extends AbstractAnnotatable, B extends Builder<T, B>>
            extends AbstractComponent.Builder<T, B> {
        private final List<Annotation> annotations = new ArrayList<>();
        Builder(String name, Type type) {
            super(name, type);
        }

        public B addAnnotation(Annotation.Builder builder) {
            return addAnnotation(builder.build());
        }

        public B addAnnotation(Annotation annotation) {
            annotations.add(annotation);
            return identity();
        }

    }
}
