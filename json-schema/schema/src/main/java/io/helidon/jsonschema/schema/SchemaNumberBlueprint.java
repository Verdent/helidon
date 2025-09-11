package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.metadata.hson.Hson;

import jakarta.json.Json;
import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint(decorator = SchemaNumberDecorator.class)
interface SchemaNumberBlueprint extends SchemaItemBlueprint {

    Optional<Double> multipleOf();

    Optional<Double> minimum();

    Optional<Double> maximum();

    Optional<Double> exclusiveMaximum();

    Optional<Double> exclusiveMinimum();

    @Option.Access("")
    @Option.Default("NUMBER")
    SchemaType schemaType();

    @Override
    default void generate(Hson.Struct.Builder builder) {
        SchemaItemBlueprint.super.generate(builder);
        multipleOf().ifPresent(multipleOf -> builder.set("multipleOf", multipleOf));
        minimum().ifPresent(minimum -> builder.set("minimum", minimum));
        maximum().ifPresent(maximum -> builder.set("maximum", maximum));
        exclusiveMaximum().ifPresent(exclusiveMaximum -> builder.set("exclusiveMaximum", exclusiveMaximum));
        exclusiveMinimum().ifPresent(exclusiveMinimum -> builder.set("exclusiveMinimum", exclusiveMinimum));
    }

}
