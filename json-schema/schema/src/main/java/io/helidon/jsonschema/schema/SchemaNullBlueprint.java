package io.helidon.jsonschema.schema;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

@Prototype.Blueprint
interface SchemaNullBlueprint extends SchemaItemBlueprint {

    @Option.Access("")
    @Option.Default("NULL")
    SchemaType schemaType();

}
