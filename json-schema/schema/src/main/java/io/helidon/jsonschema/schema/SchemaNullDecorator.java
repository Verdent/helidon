package io.helidon.jsonschema.schema;

import io.helidon.builder.api.Prototype;

class SchemaNullDecorator implements Prototype.BuilderDecorator<SchemaNull.BuilderBase<?, ?>> {

    @Override
    public void decorate(SchemaNull.BuilderBase<?, ?> target) {
        target.schemaType(SchemaType.NULL);
    }

}
