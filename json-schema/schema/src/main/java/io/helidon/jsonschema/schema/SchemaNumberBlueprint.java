package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Prototype;

import jakarta.json.Json;
import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint(decorator = SchemaNumberDecorator.class)
interface SchemaNumberBlueprint extends SchemaItemBlueprint {

    Optional<Number> multipleOf();

    Optional<Number> minimum();

    Optional<Number> maximum();

    Optional<Number> exclusiveMaximum();

    Optional<Number> exclusiveMinimum();

    @Override
    default void generate(JsonObjectBuilder builder) {
        SchemaItemBlueprint.super.generate(builder);
        builder.add("type", "number");
        multipleOf().ifPresent(multipleOf -> builder.add("multipleOf", Json.createValue(multipleOf)));
        minimum().ifPresent(minimum -> builder.add("minimum", Json.createValue(minimum)));
        maximum().ifPresent(maximum -> builder.add("maximum", Json.createValue(maximum)));
        exclusiveMaximum().ifPresent(exclusiveMaximum -> builder.add("exclusiveMaximum", Json.createValue(exclusiveMaximum)));
        exclusiveMinimum().ifPresent(exclusiveMinimum -> builder.add("exclusiveMinimum", Json.createValue(exclusiveMinimum)));
    }

}
