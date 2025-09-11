package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.metadata.hson.Hson;

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
    default void generate(Hson.Struct.Builder builder) {
        SchemaItemBlueprint.super.generate(builder);
        multipleOf().ifPresent(multipleOf -> builder.set("multipleOf", multipleOf));
        minimum().ifPresent(minimum -> builder.set("minimum", minimum));
        maximum().ifPresent(maximum -> builder.set("maximum", maximum));
        exclusiveMaximum().ifPresent(exclusiveMaximum -> builder.set("exclusiveMaximum", exclusiveMaximum));
        exclusiveMinimum().ifPresent(exclusiveMinimum -> builder.set("exclusiveMinimum", exclusiveMinimum));
    }

}
