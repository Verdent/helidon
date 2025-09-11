package io.helidon.jsonschema.schema;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import io.helidon.builder.api.Prototype;
import io.helidon.metadata.hson.Hson;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.Services;

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
    static Hson.Struct generateObject(Schema schema) {
        Hson.Struct.Builder builder = Hson.structBuilder();
        builder.set("$schema", "https://json-schema.org/draft/2020-12/schema");
        schema.id().ifPresent(id -> builder.set("$id", id));
        schema.root().generate(builder);
        return builder.build();
    }

    @Prototype.PrototypeMethod
    static Hson.Struct generateObjectNoKeywords(Schema schema) {
        Hson.Struct.Builder builder = Hson.structBuilder();
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
        try (InputStream is = new ByteArrayInputStream(jsonSchema.getBytes())) {
            Hson.Value<?> parsed = Hson.parse(is);
            Hson.Struct struct = parsed.asStruct();
            struct.stringValue("$id").ifPresent(builder::id);
            String type = struct.stringValue("type")
                    .orElseThrow(() -> new JsonSchemaException("Missing required property 'type' missing in the schema root."));
            switch (type) {
            case "string" -> builder.rootString(stringBuilder -> parseString(stringBuilder, struct));
            case "integer" -> builder.rootInteger(integerBuilder -> parseInteger(integerBuilder, struct));
            case "number" -> builder.rootNumber(numberBuilder -> parseNumber(numberBuilder, struct));
            case "boolean" -> builder.rootBoolean(booleanBuilder -> parseCommon(booleanBuilder, struct));
            case "object" -> builder.rootObject(objectBuilder -> parseObject(objectBuilder, struct));
            case "array" -> builder.rootArray(arrayBuilder -> parseArray(arrayBuilder, struct));
            case "null" -> builder.rootNull(nullBuilder -> parseCommon(nullBuilder, struct));
            default -> throw new JsonSchemaException("Unsupported root type: " + type);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return builder.build();
    }

    private static void parseCommon(SchemaItem.BuilderBase<?, ?> itemBuilder, Hson.Struct jsonObject) {
        jsonObject.stringValue("description").ifPresent(itemBuilder::description);
        jsonObject.stringValue("title").ifPresent(itemBuilder::title);
    }

    private static void parseString(SchemaString.Builder stringBuilder, Hson.Struct jsonObject) {
        parseCommon(stringBuilder, jsonObject);
        jsonObject.numberValue("maxLength").ifPresent(it -> stringBuilder.maxLength(it.longValue()));
        jsonObject.numberValue("minLength").ifPresent(it -> stringBuilder.minLength(it.longValue()));
        jsonObject.stringValue("pattern").ifPresent(stringBuilder::pattern);
    }

    private static void parseInteger(SchemaInteger.Builder integerBuilder, Hson.Struct jsonObject) {
        parseCommon(integerBuilder, jsonObject);
        jsonObject.numberValue("multipleOf").ifPresent(it -> integerBuilder.multipleOf(it.longValue()));
        jsonObject.numberValue("minimum").ifPresent(it -> integerBuilder.minimum(it.longValue()));
        jsonObject.numberValue("maximum").ifPresent(it -> integerBuilder.maximum(it.longValue()));
        jsonObject.numberValue("exclusiveMaximum").ifPresent(it -> integerBuilder.exclusiveMaximum(it.longValue()));
        jsonObject.numberValue("exclusiveMinimum").ifPresent(it -> integerBuilder.exclusiveMinimum(it.longValue()));
    }

    private static void parseNumber(SchemaNumber.Builder numberBuilder, Hson.Struct jsonObject) {
        parseCommon(numberBuilder, jsonObject);
        jsonObject.doubleValue("multipleOf").ifPresent(numberBuilder::multipleOf);
        jsonObject.doubleValue("minimum").ifPresent(numberBuilder::minimum);
        jsonObject.doubleValue("maximum").ifPresent(numberBuilder::maximum);
        jsonObject.doubleValue("exclusiveMinimum").ifPresent(numberBuilder::exclusiveMinimum);
        jsonObject.doubleValue("exclusiveMaximum").ifPresent(numberBuilder::exclusiveMaximum);
    }

    private static void parseArray(SchemaArray.Builder arrayBuilder, Hson.Struct jsonObject) {
        jsonObject.intValue("maxItems").ifPresent(arrayBuilder::maxItems);
        jsonObject.intValue("minItems").ifPresent(arrayBuilder::minItems);
        jsonObject.intValue("minContains").ifPresent(arrayBuilder::minContains);
        jsonObject.intValue("maxContains").ifPresent(arrayBuilder::maxContains);
        jsonObject.booleanValue("uniqueItems").ifPresent(arrayBuilder::uniqueItems);

        jsonObject.structValue("items")
                .ifPresent(items -> {
                    String type = items.stringValue("type")
                            .orElseThrow(() -> new JsonSchemaException("Missing required property 'type' missing in the object property"
                                                                               + "."));
                    switch (type) {
                    case "string" -> arrayBuilder.itemsString(stringBuilder -> parseString(stringBuilder, items));
                    case "integer" -> arrayBuilder.itemsInteger(integerBuilder -> parseInteger(integerBuilder, items));
                    case "number" -> arrayBuilder.itemsNumber(numberBuilder -> parseNumber(numberBuilder, items));
                    case "boolean" -> arrayBuilder.itemsBoolean(booleanBuilder -> parseCommon(booleanBuilder, items));
                    case "object" -> arrayBuilder.itemsObject(objectBuilder -> parseObject(objectBuilder, items));
                    case "array" -> arrayBuilder.itemsArray(arrayBuilder2 -> parseArray(arrayBuilder2, items));
                    case "null" -> arrayBuilder.itemsNull(nullBuilder -> parseCommon(nullBuilder, items));
                    default -> throw new JsonSchemaException("Unsupported type: " + type);
                    }
                });
    }

    private static void parseObject(SchemaObject.Builder objectBuilder, Hson.Struct jsonObject) {
        parseCommon(objectBuilder, jsonObject);
        jsonObject.intValue("maxProperties").ifPresent(objectBuilder::maxProperties);
        jsonObject.intValue("minProperties").ifPresent(objectBuilder::minProperties);
        jsonObject.booleanValue("additionalProperties").ifPresent(objectBuilder::additionalProperties);
        jsonObject.structValue("properties")
                .ifPresent(properties -> {
                    List<String> requiredProperties = jsonObject.stringArray("required").orElse(List.of());
                    properties.values()
                            .forEach((key, value) -> {
                                Hson.Struct object = value.asStruct();
                                String type = object.stringValue("type")
                                        .orElseThrow(() -> new JsonSchemaException(
                                                "Missing required property 'type' missing in the object property"
                                                        + "."));
                                switch (type) {
                                case "string" -> objectBuilder.addStringProperty(key, stringBuilder -> {
                                    parseString(stringBuilder, object);
                                    stringBuilder.required(requiredProperties.contains(key));
                                });
                                case "integer" -> objectBuilder.addIntegerProperty(key, integerBuilder -> {
                                    parseInteger(integerBuilder, object);
                                    integerBuilder.required(requiredProperties.contains(key));
                                });
                                case "number" -> objectBuilder.addNumberProperty(key, numberBuilder -> {
                                    parseNumber(numberBuilder, object);
                                    numberBuilder.required(requiredProperties.contains(key));
                                });
                                case "boolean" -> objectBuilder.addBooleanProperty(key, booleanBuilder -> {
                                    parseCommon(booleanBuilder, object);
                                    booleanBuilder.required(requiredProperties.contains(key));
                                });
                                case "object" -> objectBuilder.addObjectProperty(key, objectBuilder2 -> {
                                    parseObject(objectBuilder2, object);
                                    objectBuilder2.required(requiredProperties.contains(key));
                                });
                                case "array" -> objectBuilder.addArrayProperty(key, arrayBuilder -> {
                                    parseArray(arrayBuilder, object);
                                    arrayBuilder.required(requiredProperties.contains(key));
                                });
                                case "null" -> objectBuilder.addNullProperty(key, nullBuilder -> {
                                    parseCommon(nullBuilder, object);
                                    nullBuilder.required(requiredProperties.contains(key));
                                });
                                default -> throw new JsonSchemaException("Unsupported type: " + type);
                                }
                            });
                });
    }

}
