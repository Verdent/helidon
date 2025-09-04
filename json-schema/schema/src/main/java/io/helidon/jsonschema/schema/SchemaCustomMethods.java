package io.helidon.jsonschema.schema;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import io.helidon.builder.api.Prototype;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.Services;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonGeneratorFactory;

class SchemaCustomMethods {

    @Prototype.PrototypeMethod
    static String generate(Schema schema) {
        Map<String, Boolean> map = Map.of(JsonGenerator.PRETTY_PRINTING, true);
        JsonGeneratorFactory generatorFactory = Json.createGeneratorFactory(map);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            try (JsonGenerator generator = generatorFactory.createGenerator(outputStream)) {
                generator.write(generateObject(schema));
            }
            return outputStream.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Prototype.PrototypeMethod
    static String generateNoKeywords(Schema schema) {
        Map<String, Boolean> map = Map.of(JsonGenerator.PRETTY_PRINTING, true);
        JsonGeneratorFactory generatorFactory = Json.createGeneratorFactory(map);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            try (JsonGenerator generator = generatorFactory.createGenerator(outputStream)) {
                generator.write(generateObjectNoKeywords(schema));
            }
            return outputStream.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Prototype.PrototypeMethod
    static JsonObject generateObject(Schema schema) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("$schema", "https://json-schema.org/draft/2020-12/schema");
        schema.id().ifPresent(id -> builder.add("$id", id));
        schema.root().generate(builder);
        return builder.build();
    }

    @Prototype.PrototypeMethod
    static JsonObject generateObjectNoKeywords(Schema schema) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        schema.root().generate(builder);
        return builder.build();
    }

    @Prototype.FactoryMethod
    static Schema create(Class<?> clazz) {
        return Services.get(JsonSchemaProvider.class, Qualifier.createNamed(clazz)).schema();
    }

    @Prototype.FactoryMethod
    static Schema parse(String jsonSchema) {
        Schema.Builder builder = Schema.builder();
        try (JsonReader reader = Json.createReader(new StringReader(jsonSchema))) {
            JsonObject jsonObject = reader.readObject();
            getStringValue(jsonObject, "$id").ifPresent(builder::id);
            String type = getStringValue(jsonObject, "type")
                    .orElseThrow(() -> new SchemaException("Missing required property 'type' missing in the schema root."));
            switch (type) {
            case "string" -> builder.rootString(stringBuilder -> parseString(stringBuilder, jsonObject));
            case "integer" -> builder.rootInteger(integerBuilder -> parseInteger(integerBuilder, jsonObject));
            case "number" -> builder.rootNumber(numberBuilder -> parseNumber(numberBuilder, jsonObject));
            case "boolean" -> builder.rootBoolean(booleanBuilder -> parseCommon(booleanBuilder, jsonObject));
            case "object" -> builder.rootObject(objectBuilder -> parseObject(objectBuilder, jsonObject));
            case "array" -> builder.rootArray(arrayBuilder -> parseArray(arrayBuilder, jsonObject));
            default -> throw new SchemaException("Unsupported root type: " + type);
            }
        }
        return builder.build();
    }

    private static void parseCommon(SchemaItem.BuilderBase<?, ?> itemBuilder, JsonObject jsonObject) {
        getStringValue(jsonObject, "description").ifPresent(itemBuilder::description);
        getStringValue(jsonObject, "title").ifPresent(itemBuilder::title);
    }

    private static void parseString(SchemaString.Builder stringBuilder, JsonObject jsonObject) {
        parseCommon(stringBuilder, jsonObject);
        getLongValue(jsonObject, "maxLength").ifPresent(stringBuilder::maxLength);
        getLongValue(jsonObject, "minLength").ifPresent(stringBuilder::minLength);
        getStringValue(jsonObject, "pattern").ifPresent(stringBuilder::pattern);
    }

    private static void parseInteger(SchemaInteger.Builder integerBuilder, JsonObject jsonObject) {
        parseCommon(integerBuilder, jsonObject);
        getLongValue(jsonObject, "multipleOf").ifPresent(integerBuilder::multipleOf);
        getLongValue(jsonObject, "minimum").ifPresent(integerBuilder::minimum);
        getLongValue(jsonObject, "maximum").ifPresent(integerBuilder::maximum);
        getLongValue(jsonObject, "exclusiveMaximum").ifPresent(integerBuilder::exclusiveMaximum);
        getLongValue(jsonObject, "exclusiveMinimum").ifPresent(integerBuilder::exclusiveMinimum);
    }

    private static void parseNumber(SchemaNumber.Builder numberBuilder, JsonObject jsonObject) {
        parseCommon(numberBuilder, jsonObject);
        getDoubleValue(jsonObject, "multipleOf").ifPresent(numberBuilder::multipleOf);
        getDoubleValue(jsonObject, "minimum").ifPresent(numberBuilder::minimum);
        getDoubleValue(jsonObject, "maximum").ifPresent(numberBuilder::maximum);
        getDoubleValue(jsonObject, "exclusiveMaximum").ifPresent(numberBuilder::exclusiveMaximum);
        getDoubleValue(jsonObject, "exclusiveMinimum").ifPresent(numberBuilder::exclusiveMinimum);
    }

    private static void parseArray(SchemaArray.Builder arrayBuilder, JsonObject jsonObject) {

    }

    private static void parseObject(SchemaObject.Builder objectBuilder, JsonObject jsonObject) {
        parseCommon(objectBuilder, jsonObject);
        getIntValue(jsonObject, "maxProperties").ifPresent(objectBuilder::maxProperties);
        getIntValue(jsonObject, "minProperties").ifPresent(objectBuilder::minProperties);
        getBooleanValue(jsonObject, "dependentRequired").ifPresent(objectBuilder::dependentRequired);
        JsonObject properties = jsonObject.getJsonObject("properties");
        if (properties != null) {
            JsonArray required = jsonObject.getJsonArray("required");
            Set<String> requiredProperties;
            if (required != null) {
                requiredProperties = required.getValuesAs(JsonString.class)
                        .stream()
                        .map(JsonString::getString)
                        .collect(Collectors.toSet());
            } else {
                requiredProperties = Set.of();
            }
            properties.forEach((key, value) -> {
                JsonObject object = (JsonObject) value;
                String type = getStringValue(object, "type")
                        .orElseThrow(() -> new SchemaException("Missing required property 'type' missing in the object property"
                                                                       + "."));
                switch (type) {
                case "string" -> objectBuilder.putStringProperty(key, stringBuilder -> {
                    parseString(stringBuilder, object);
                    stringBuilder.required(requiredProperties.contains(key));
                });
                case "integer" -> objectBuilder.putIntegerProperty(key, integerBuilder -> {
                    parseInteger(integerBuilder, object);
                    integerBuilder.required(requiredProperties.contains(key));
                });
                case "number" -> objectBuilder.putNumberProperty(key, numberBuilder -> {
                    parseNumber(numberBuilder, object);
                    numberBuilder.required(requiredProperties.contains(key));
                });
                case "boolean" -> objectBuilder.putBooleanProperty(key, booleanBuilder -> {
                    parseCommon(booleanBuilder, object);
                    booleanBuilder.required(requiredProperties.contains(key));
                });
                case "object" -> objectBuilder.putObjectProperty(key, objectBuilder2 -> {
                    parseObject(objectBuilder2, object);
                    objectBuilder2.required(requiredProperties.contains(key));
                });
                case "array" -> objectBuilder.putArrayProperty(key, arrayBuilder -> {
                    parseArray(arrayBuilder, object);
                    arrayBuilder.required(requiredProperties.contains(key));
                });
                default -> throw new SchemaException("Unsupported type: " + type);
                }
            });
        }
    }

    private static Optional<String> getStringValue(JsonObject jsonObject, String key) {
        return Optional.ofNullable(jsonObject.getString(key, null));
    }

    private static Optional<Long> getLongValue(JsonObject jsonObject, String key) {
        JsonNumber jsonNumber = jsonObject.getJsonNumber(key);
        if (jsonNumber == null) {
            return Optional.empty();
        }
        return Optional.of(jsonNumber.longValue());
    }

    private static Optional<Integer> getIntValue(JsonObject jsonObject, String key) {
        JsonNumber jsonNumber = jsonObject.getJsonNumber(key);
        if (jsonNumber == null) {
            return Optional.empty();
        }
        return Optional.of(jsonNumber.intValue());
    }

    private static Optional<Double> getDoubleValue(JsonObject jsonObject, String key) {
        JsonNumber jsonNumber = jsonObject.getJsonNumber(key);
        if (jsonNumber == null) {
            return Optional.empty();
        }
        return Optional.of(jsonNumber.doubleValue());
    }

    private static Optional<Boolean> getBooleanValue(JsonObject jsonObject, String key) {
        JsonValue jsonValue = jsonObject.get(key);
        if (jsonValue == null) {
            return Optional.empty();
        } else if (jsonValue == JsonValue.TRUE) {
            return Optional.of(true);
        }
        return Optional.of(false);
    }

}
