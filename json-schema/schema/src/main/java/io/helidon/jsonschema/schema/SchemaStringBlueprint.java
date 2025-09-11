package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint(decorator = SchemaStringDecorator.class)
interface SchemaStringBlueprint extends SchemaItemBlueprint {

    Optional<Long> maxLength();

    Optional<Long> minLength();

    Optional<String> pattern();

    @Option.Access("")
    @Option.Default("STRING")
    SchemaType schemaType();

    @Override
    default void generate(JsonObjectBuilder builder) {
        SchemaItemBlueprint.super.generate(builder);
        maxLength().ifPresent(maxLength -> builder.add("maxLength", maxLength));
        minLength().ifPresent(minLength -> builder.add("minLength", minLength));
        pattern().ifPresent(pattern -> builder.add("pattern", pattern));
    }

}
