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

    Optional<Boolean> dependentRequired();

    @Option.Singular("property")
    @Option.Access("")
    Map<String, SchemaItem> properties();

    @Option.Singular("stringProperty")
    Map<String, SchemaString> stringProperties();

    @Option.Singular("objectProperty")
    Map<String, SchemaObject> objectProperties();

    @Option.Singular("arrayProperty")
    Map<String, SchemaArray> arrayProperties();

    @Option.Singular("numberProperty")
    Map<String, SchemaNumber> numberProperties();

    @Option.Singular("integerProperty")
    Map<String, SchemaInteger> integerProperties();

    @Option.Singular("booleanProperty")
    Map<String, SchemaBoolean> booleanProperties();

    @Override
    default void generate(JsonObjectBuilder builder) {
        SchemaItemBlueprint.super.generate(builder);
        builder.add("type", "object");
        maxProperties().ifPresent(maxProperties -> builder.add("maxProperties", maxProperties));
        minProperties().ifPresent(minProperties -> builder.add("minProperties", minProperties));
        dependentRequired().ifPresent(dependentRequired -> builder.add("dependentRequired", dependentRequired));
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
