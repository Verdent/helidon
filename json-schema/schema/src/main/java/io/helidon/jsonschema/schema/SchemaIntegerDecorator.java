package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Prototype;

class SchemaIntegerDecorator implements Prototype.BuilderDecorator<SchemaInteger.BuilderBase<?, ?>> {

    @Override
    public void decorate(SchemaInteger.BuilderBase<?, ?> target) {
        Optional<Long> minimum = target.minimum();
        Optional<Long> exclusiveMinimum = target.exclusiveMinimum();
        Optional<Long> maximum = target.maximum();
        Optional<Long> exclusiveMaximum = target.exclusiveMaximum();
        if (minimum.isPresent() && exclusiveMinimum.isPresent()) {
            throw new JsonSchemaException("Both minimum and exclusive minimum cannot be set at the same time");
        }
        if (maximum.isPresent() && exclusiveMaximum.isPresent()) {
            throw new JsonSchemaException("Both maximum and exclusive maximum cannot be set at the same time");
        }
        Optional<Long> minimumNumber = minimum.or(() -> exclusiveMinimum);
        Optional<Long> maximumNumber = maximum.or(() -> exclusiveMaximum);
        if (minimumNumber.isPresent() && maximumNumber.isPresent()) {
            if (minimumNumber.get() > maximumNumber.get()) {
                throw new JsonSchemaException("Minimum value cannot be greater than the maximum value");
            }
        }
        if (minimumNumber.isPresent() && minimumNumber.get() < 0) {
            throw new JsonSchemaException("Minimum value cannot be lower than 0");
        }
        if (maximumNumber.isPresent() && maximumNumber.get() < 0) {
            throw new JsonSchemaException("Maximum value cannot be lower than 0");
        }
    }

}
