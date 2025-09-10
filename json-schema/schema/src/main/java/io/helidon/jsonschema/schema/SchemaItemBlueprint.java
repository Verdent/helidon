package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint
interface SchemaItemBlueprint {

    Optional<String> title();

    Optional<String> description();

    boolean required();

    @Option.Access("")
    SchemaType schemaType();

    default void generate(JsonObjectBuilder builder) {
        title().ifPresent(title -> builder.add("title", title));
        description().ifPresent(description -> builder.add("description", description));
    }

}
