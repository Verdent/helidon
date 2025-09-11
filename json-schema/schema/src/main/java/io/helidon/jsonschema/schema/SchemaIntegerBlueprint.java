package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint(decorator = SchemaIntegerDecorator.class)
@Prototype.CustomMethods(SchemaIntegerCustomMethods.class)
interface SchemaIntegerBlueprint extends SchemaItemBlueprint {

    Optional<Long> multipleOf();

    Optional<Long> minimum();

    Optional<Long> maximum();

    Optional<Long> exclusiveMaximum();

    Optional<Long> exclusiveMinimum();

    @Option.Access("")
    @Option.Default("INTEGER")
    SchemaType schemaType();

    @Override
    default void generate(JsonObjectBuilder builder) {
        SchemaItemBlueprint.super.generate(builder);
        multipleOf().ifPresent(multipleOf -> builder.add("multipleOf", multipleOf));
        minimum().ifPresent(minimum -> builder.add("minimum", minimum));
        maximum().ifPresent(maximum -> builder.add("maximum", maximum));
        exclusiveMaximum().ifPresent(exclusiveMaximum -> builder.add("exclusiveMaximum", exclusiveMaximum));
        exclusiveMinimum().ifPresent(exclusiveMinimum -> builder.add("exclusiveMinimum", exclusiveMinimum));
    }

}
