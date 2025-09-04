package io.helidon.jsonschema.schema;

import io.helidon.builder.api.Prototype;

import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint
interface SchemaBooleanBlueprint extends SchemaItemBlueprint {

    @Override
    default void generate(JsonObjectBuilder builder) {
        SchemaItemBlueprint.super.generate(builder);
        builder.add("type", "boolean");
    }

}
