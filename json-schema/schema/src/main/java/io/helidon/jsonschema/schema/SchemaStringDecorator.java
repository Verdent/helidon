package io.helidon.jsonschema.schema;

import io.helidon.builder.api.Prototype;

class SchemaStringDecorator implements Prototype.BuilderDecorator<SchemaString.BuilderBase<?, ?>> {

    @Override
    public void decorate(SchemaString.BuilderBase<?, ?> target) {
        target.schemaType(SchemaType.STRING);
    }

}
