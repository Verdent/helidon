package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Prototype;

class SchemaArrayDecorator implements Prototype.BuilderDecorator<SchemaArray.BuilderBase<?, ?>> {

    @Override
    public void decorate(SchemaArray.BuilderBase<?, ?> target) {
        target.schemaType(SchemaType.ARRAY);
        target.itemsObject().ifPresent(target::items);
        addRoot(target, target.itemsArray());
        addRoot(target, target.itemsInteger());
        addRoot(target, target.itemsNumber());
        addRoot(target, target.itemsString());
        addRoot(target, target.itemsBoolean());
        addRoot(target, target.itemsNull());
    }

    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    private static void addRoot(SchemaArray.BuilderBase<?, ?> target, Optional<? extends SchemaItem> item) {
        if (target.items().isEmpty()) {
            item.ifPresent(target::items);
        } else if (item.isPresent()) {
            throw new SchemaException("Only one array items type is supported");
        }
    }

}
