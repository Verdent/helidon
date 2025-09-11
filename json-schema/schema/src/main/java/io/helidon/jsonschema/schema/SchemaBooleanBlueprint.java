package io.helidon.jsonschema.schema;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint
interface SchemaBooleanBlueprint extends SchemaItemBlueprint {

    @Option.Access("")
    @Option.Default("BOOLEAN")
    SchemaType schemaType();

}
