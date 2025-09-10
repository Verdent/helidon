package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Prototype;

class SchemaNumberDecorator implements Prototype.BuilderDecorator<SchemaNumber.BuilderBase<?, ?>> {

    @Override
    public void decorate(SchemaNumber.BuilderBase<?, ?> target) {
        target.schemaType(SchemaType.NUMBER);
        Optional<Number> minimum = target.minimum();
        Optional<Number> exclusiveMinimum = target.exclusiveMinimum();
        Optional<Number> maximum = target.maximum();
        Optional<Number> exclusiveMaximum = target.exclusiveMaximum();
        if (minimum.isPresent() && exclusiveMinimum.isPresent()) {
            throw new SchemaException("Both minimum and exclusive minimum cannot be set at the same time");
        }
        if (maximum.isPresent() && exclusiveMaximum.isPresent()) {
            throw new SchemaException("Both maximum and exclusive maximum cannot be set at the same time");
        }
        Optional<Number> minimumNumber = minimum.or(() -> exclusiveMinimum);
        Optional<Number> maximumNumber = maximum.or(() -> exclusiveMaximum);
        if (minimumNumber.isPresent() && maximumNumber.isPresent()) {
            if (minimumNumber.get().doubleValue() > maximumNumber.get().doubleValue()) {
                throw new SchemaException("Minimum value cannot be greater than the maximum value");
            }
        }
        if (minimumNumber.isPresent() && minimumNumber.get().doubleValue() < 0) {
            throw new SchemaException("Minimum value cannot be lower than 0");
        }
        if (maximumNumber.isPresent() && maximumNumber.get().doubleValue() < 0) {
            throw new SchemaException("Maximum value cannot be lower than 0");
        }
    }

}
