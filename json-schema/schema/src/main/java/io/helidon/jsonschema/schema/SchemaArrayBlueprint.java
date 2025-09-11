package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.metadata.hson.Hson;
import io.helidon.metadata.hson.HsonStruct;

import jakarta.json.Json;
import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint(decorator = SchemaArrayDecorator.class)
interface SchemaArrayBlueprint extends SchemaItemBlueprint {

    Optional<Integer> maxItems();

    Optional<Integer> minItems();

    Optional<Integer> minContains();

    Optional<Integer> maxContains();

    Optional<Boolean> uniqueItems();

    @Option.Access("")
    Optional<SchemaItem> items();

    Optional<SchemaObject> itemsObject();

    Optional<SchemaArray> itemsArray();

    Optional<SchemaNumber> itemsNumber();

    Optional<SchemaInteger> itemsInteger();

    Optional<SchemaString> itemsString();

    Optional<SchemaBoolean> itemsBoolean();

    Optional<SchemaNull> itemsNull();

    @Option.Access("")
    @Option.Default("ARRAY")
    SchemaType schemaType();

    @Override
    default void generate(Hson.Struct.Builder builder) {
        SchemaItemBlueprint.super.generate(builder);
        maxItems().ifPresent(maxItems -> builder.set("maxItems", maxItems));
        minItems().ifPresent(minItems -> builder.set("minItems", minItems));
        minContains().ifPresent(minContains -> builder.set("minContains", minContains));
        maxContains().ifPresent(maxContains -> builder.set("maxContains", maxContains));
        uniqueItems().ifPresent(uniqueItems -> builder.set("uniqueItems", uniqueItems));
        items().ifPresent(items -> {
            Hson.Struct.Builder objectBuilder = Hson.structBuilder();
            items.generate(objectBuilder);
            builder.set("items", objectBuilder.build());
        });
    }
}
