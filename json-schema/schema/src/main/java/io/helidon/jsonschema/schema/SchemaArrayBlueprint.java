package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Prototype;

import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint
interface SchemaArrayBlueprint extends SchemaItemBlueprint {

    Optional<Integer> maxItems();

    Optional<Integer> minItems();

    Optional<Integer> minContains();

    Optional<Integer> maxContains();

    Optional<Boolean> uniqueItems();

    @Override
    default void generate(JsonObjectBuilder builder) {
        SchemaItemBlueprint.super.generate(builder);
        builder.add("type", "array");
        maxItems().ifPresent(maxItems -> builder.add("maxItems", maxItems));
        minItems().ifPresent(minItems -> builder.add("minItems", minItems));
        minContains().ifPresent(minContains -> builder.add("minContains", minContains));
        maxContains().ifPresent(maxContains -> builder.add("maxContains", maxContains));
        uniqueItems().ifPresent(uniqueItems -> builder.add("uniqueItems", uniqueItems));
    }
}
