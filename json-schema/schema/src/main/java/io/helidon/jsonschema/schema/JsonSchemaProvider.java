package io.helidon.jsonschema.schema;

public interface JsonSchemaProvider {

    Class<?> schemaClass();

    String schema();

    String schemaNoKeywords();

}
