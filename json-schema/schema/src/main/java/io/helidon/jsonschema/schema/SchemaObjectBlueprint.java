package io.helidon.jsonschema.schema;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObjectBuilder;

@Prototype.Blueprint(decorator = SchemaObjectDecorator.class)
interface SchemaObjectBlueprint extends SchemaItemBlueprint {

    Optional<Integer> maxProperties();

    Optional<Integer> minProperties();

    Optional<Boolean> additionalProperties();

    @Option.Singular("property")
    @Option.Access("")
    Map<String, SchemaItem> properties();

    @Option.Singular(value = "addStringProperty", withPrefix = false)
    Map<String, SchemaString> stringProperties();

    @Option.Singular(value = "addObjectProperty", withPrefix = false)
    Map<String, SchemaObject> objectProperties();

    @Option.Singular(value = "addArrayProperty", withPrefix = false)
    Map<String, SchemaArray> arrayProperties();

    @Option.Singular(value = "addNumberProperty", withPrefix = false)
    Map<String, SchemaNumber> numberProperties();

    @Option.Singular(value = "addIntegerProperty", withPrefix = false)
    Map<String, SchemaInteger> integerProperties();

    @Option.Singular(value = "addBooleanProperty", withPrefix = false)
    Map<String, SchemaBoolean> booleanProperties();

    @Option.Singular(value = "addNullProperty", withPrefix = false)
    Map<String, SchemaNull> nullProperties();

    @Option.Access("")
    @Option.Default("OBJECT")
    SchemaType schemaType();

    @Override
    default void generate(JsonObjectBuilder builder) {
        SchemaItemBlueprint.super.generate(builder);
        maxProperties().ifPresent(maxProperties -> builder.add("maxProperties", maxProperties));
        minProperties().ifPresent(minProperties -> builder.add("minProperties", minProperties));
        additionalProperties()
                .ifPresent(additionalProperties -> builder.add("additionalProperties", additionalProperties));
        Set<String> requiredProperties = new HashSet<>();
        Map<String, SchemaItem> properties = properties();
        if (!properties.isEmpty()) {
            JsonObjectBuilder objectBuilder = Json.createObjectBuilder();
            for (Map.Entry<String, SchemaItem> entry : properties.entrySet()) {
                SchemaItem schemaItem = entry.getValue();
                JsonObjectBuilder itemBuilder = Json.createObjectBuilder();
                schemaItem.generate(itemBuilder);
                objectBuilder.add(entry.getKey(), itemBuilder);
                if (schemaItem.required()) {
                    requiredProperties.add(entry.getKey());
                }
            }
            builder.add("properties", objectBuilder);
        }
        if (!requiredProperties.isEmpty()) {
            JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
            requiredProperties.forEach(arrayBuilder::add);
            builder.add("required", arrayBuilder);
        }
    }
}
