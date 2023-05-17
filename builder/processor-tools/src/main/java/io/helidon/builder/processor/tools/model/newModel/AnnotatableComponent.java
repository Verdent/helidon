package io.helidon.builder.processor.tools.model.newModel;

import java.util.ArrayList;
import java.util.List;

abstract class AnnotatableComponent extends CommonComponent {

    private final List<Annotation> annotations;

    AnnotatableComponent(Builder<?, ?> builder) {
        super(builder);
        annotations = List.copyOf(builder.annotations);
    }

    @Override
    void  addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        annotations.forEach(annotation -> annotation.addImports(imports));
    }

    List<Annotation> annotations() {
        return annotations;
    }

    static abstract class Builder<B extends Builder<B, T>, T extends AnnotatableComponent> extends CommonComponent.Builder<B, T> {

        private final List<Annotation> annotations = new ArrayList<>();

        Builder() {
        }

        public B addAnnotation(Annotation.Builder builder) {
            return addAnnotation(builder.build());
        }

        public B addAnnotation(Annotation annotation) {
            annotations.add(annotation);
            return identity();
        }

        @Override
        public B name(String name) {
            return super.name(name);
        }

    }

}
