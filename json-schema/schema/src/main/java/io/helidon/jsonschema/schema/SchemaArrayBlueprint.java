package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
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

    @Override
    default void generate(JsonObjectBuilder builder) {
        SchemaItemBlueprint.super.generate(builder);
        builder.add("type", "array");
        maxItems().ifPresent(maxItems -> builder.add("maxItems", maxItems));
        minItems().ifPresent(minItems -> builder.add("minItems", minItems));
        minContains().ifPresent(minContains -> builder.add("minContains", minContains));
        maxContains().ifPresent(maxContains -> builder.add("maxContains", maxContains));
        uniqueItems().ifPresent(uniqueItems -> builder.add("uniqueItems", uniqueItems));
        items().ifPresent(items -> {
            JsonObjectBuilder objectBuilder = Json.createObjectBuilder();
            items.generate(objectBuilder);
            builder.add("items", objectBuilder);
        });
    }
}
