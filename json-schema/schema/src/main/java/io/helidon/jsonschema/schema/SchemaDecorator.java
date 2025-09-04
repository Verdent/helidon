package io.helidon.jsonschema.schema;

import io.helidon.builder.api.Prototype;

class SchemaDecorator implements Prototype.BuilderDecorator<Schema.BuilderBase<?, ?>> {

    @Override
    public void decorate(Schema.BuilderBase<?, ?> target) {
        target.rootObject().ifPresent(target::root);
        target.rootArray().ifPresent(target::root);
        target.rootInteger().ifPresent(target::root);
        target.rootNumber().ifPresent(target::root);
        target.rootString().ifPresent(target::root);
        target.rootBoolean().ifPresent(target::root);
    }

}
