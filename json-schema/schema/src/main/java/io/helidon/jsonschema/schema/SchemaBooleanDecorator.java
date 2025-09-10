package io.helidon.jsonschema.schema;

import io.helidon.builder.api.Prototype;

class SchemaBooleanDecorator implements Prototype.BuilderDecorator<SchemaBoolean.BuilderBase<?, ?>> {

    @Override
    public void decorate(SchemaBoolean.BuilderBase<?, ?> target) {
        target.schemaType(SchemaType.BOOLEAN);
    }

}
