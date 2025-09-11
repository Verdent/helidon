package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.metadata.hson.Hson;

import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint
interface SchemaItemBlueprint {

    Optional<String> title();

    Optional<String> description();

    boolean required();

    @Option.Access("")
    SchemaType schemaType();

    @Deprecated(forRemoval = true)
    default void generate(Hson.Struct.Builder builder) {
        title().ifPresent(title -> builder.set("title", title));
        description().ifPresent(description -> builder.set("description", description));
        builder.set("type", schemaType().name().toLowerCase());
    }

}
