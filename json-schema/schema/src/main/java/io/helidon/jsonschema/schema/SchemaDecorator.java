package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Prototype;

class SchemaDecorator implements Prototype.BuilderDecorator<Schema.BuilderBase<?, ?>> {

    @Override
    public void decorate(Schema.BuilderBase<?, ?> target) {
        target.rootObject().ifPresent(target::root);
        addRoot(target, target.rootArray());
        addRoot(target, target.rootInteger());
        addRoot(target, target.rootNumber());
        addRoot(target, target.rootString());
        addRoot(target, target.rootBoolean());
        addRoot(target, target.rootNull());
    }

    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    private static void addRoot(Schema.BuilderBase<?, ?> target, Optional<? extends SchemaItem> item) {
        if (target.root().isEmpty()) {
            item.ifPresent(target::root);
        } else if (item.isPresent()) {
            throw new JsonSchemaException("Only one root type is supported");
        }
    }

}
