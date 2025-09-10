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

        Optional<Integer> minContains = target.minContains();
        Optional<Integer> maxContains = target.maxContains();
        if (minContains.isPresent() && maxContains.isPresent()) {
            if (minContains.get() > maxContains.get()) {
                throw new SchemaException("Minimum contains value cannot be greater than the maximum value");
            }
        }
        if (minContains.isPresent() && minContains.get() < 0) {
            throw new SchemaException("Minimum contains cannot be lower than 0");
        }
        if (maxContains.isPresent() && maxContains.get() < 0) {
            throw new SchemaException("Maximum contains cannot be lower than 0");
        }

        Optional<Integer> minItems = target.minItems();
        Optional<Integer> maxItems = target.maxItems();
        if (minItems.isPresent() && maxItems.isPresent()) {
            if (minItems.get() > maxItems.get()) {
                throw new SchemaException("Minimum items value cannot be greater than the maximum value");
            }
        }
        if (minItems.isPresent() && minItems.get() < 0) {
            throw new SchemaException("Minimum items cannot be lower than 0");
        }
        if (maxItems.isPresent() && maxItems.get() < 0) {
            throw new SchemaException("Maximum items cannot be lower than 0");
        }
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
