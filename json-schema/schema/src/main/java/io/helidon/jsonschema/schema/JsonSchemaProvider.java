package io.helidon.jsonschema.schema;

public interface JsonSchemaProvider {

    Class<?> schemaClass();

    String jsonSchema();

    Schema schema();

}
