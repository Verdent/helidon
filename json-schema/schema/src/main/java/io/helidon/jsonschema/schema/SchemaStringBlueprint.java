package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.metadata.hson.Hson;

@Prototype.Blueprint(decorator = SchemaStringDecorator.class)
interface SchemaStringBlueprint extends SchemaItemBlueprint {

    Optional<Long> maxLength();

    Optional<Long> minLength();

    Optional<String> pattern();

    @Option.Access("")
    @Option.Default("STRING")
    SchemaType schemaType();

    @Override
    default void generate(Hson.Struct.Builder builder) {
        SchemaItemBlueprint.super.generate(builder);
        maxLength().ifPresent(maxLength -> builder.set("maxLength", maxLength));
        minLength().ifPresent(minLength -> builder.set("minLength", minLength));
        pattern().ifPresent(pattern -> builder.set("pattern", pattern));
    }

}
