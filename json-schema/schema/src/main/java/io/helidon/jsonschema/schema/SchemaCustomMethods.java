package io.helidon.jsonschema.schema;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

import io.helidon.builder.api.Prototype;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.Services;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
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

//    @Prototype.FactoryMethod
//    static Schema create(Class<?> clazz) {
//        return Services.get(JsonSchemaProvider.class, Qualifier.createNamed(clazz)).schema();
//    }

}
