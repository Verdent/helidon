package io.helidon.jsonschema.schema;

import io.helidon.builder.api.Prototype;

class SchemaObjectDecorator implements Prototype.BuilderDecorator<SchemaObject.BuilderBase<?, ?>> {

    @Override
    public void decorate(SchemaObject.BuilderBase<?, ?> target) {
        target.integerProperties().forEach(target.properties()::putIfAbsent);
        target.numberProperties().forEach(target.properties()::putIfAbsent);
        target.stringProperties().forEach(target.properties()::putIfAbsent);
        target.booleanProperties().forEach(target.properties()::putIfAbsent);
        target.objectProperties().forEach(target.properties()::putIfAbsent);
        target.arrayProperties().forEach(target.properties()::putIfAbsent);
        target.nullProperties().forEach(target.properties()::putIfAbsent);
    }

}
