package io.helidon.jsonschema.generator;

import io.helidon.common.types.TypeName;

class Types {

    //Common annotations
    static final TypeName JSON_SCHEMA_SCHEMA = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Schema");
    static final TypeName JSON_SCHEMA_TITLE = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Title");
    static final TypeName JSON_SCHEMA_DESCRIPTION = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Description");
    static final TypeName JSON_SCHEMA_REQUIRED = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Required");
    static final TypeName JSON_SCHEMA_PROVIDER = TypeName.create("io.helidon.jsonschema.schema.JsonSchemaProvider");

    //Integer annotations
    static final TypeName JSON_SCHEMA_INTEGER_MULTIPLE_OF =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Integer.MultipleOf");
    static final TypeName JSON_SCHEMA_INTEGER_MINIMUM =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Integer.Minimum");
    static final TypeName JSON_SCHEMA_INTEGER_MAXIMUM =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Integer.Maximum");
    static final TypeName JSON_SCHEMA_INTEGER_EXCLUSIVE_MAXIMUM =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Integer.ExclusiveMaximum");
    static final TypeName JSON_SCHEMA_INTEGER_EXCLUSIVE_MINIMUM =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Integer.ExclusiveMinimum");

    //String annotations
    static final TypeName JSON_SCHEMA_STRING_MIN_LENGTH =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.String.MinLength");
    static final TypeName JSON_SCHEMA_STRING_MAX_LENGTH =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.String.MaxLength");
    static final TypeName JSON_SCHEMA_STRING_PATTERN =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.String.Pattern");

    //Object annotations
    static final TypeName JSON_SCHEMA_OBJECT_MIN_PROPERTIES =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.String.MinProperties");
    static final TypeName JSON_SCHEMA_OBJECT_MAX_PROPERTIES =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.String.MaxProperties");

    //Number annotations
    static final TypeName JSON_SCHEMA_NUMBER_MULTIPLE_OF =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Number.MultipleOf");
    static final TypeName JSON_SCHEMA_NUMBER_MINIMUM =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Number.Minimum");
    static final TypeName JSON_SCHEMA_NUMBER_MAXIMUM =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Number.Maximum");
    static final TypeName JSON_SCHEMA_NUMBER_EXCLUSIVE_MAXIMUM =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Number.ExclusiveMaximum");
    static final TypeName JSON_SCHEMA_NUMBER_EXCLUSIVE_MINIMUM =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Number.ExclusiveMinimum");

    static final TypeName SCHEMA = TypeName.create("io.helidon.jsonschema.schema.Schema");
    static final TypeName SCHEMA_BUILDER = TypeName.create("io.helidon.jsonschema.schema.Schema.Builder");
    static final TypeName SCHEMA_OBJECT = TypeName.create("io.helidon.jsonschema.schema.SchemaObject");
    static final TypeName SCHEMA_OBJECT_BUILDER = TypeName.create("io.helidon.jsonschema.schema.SchemaObject.Builder");

    static final TypeName LAZY_VALUE = TypeName.create("io.helidon.common.LazyValue");
    static final TypeName LAZY_VALUE_SCHEMA = TypeName.builder(Types.LAZY_VALUE)
            .addTypeArgument(Types.SCHEMA)
            .build();


    //Service registry related annotations
    static final TypeName SERVICE_NAMED_BY_TYPE = TypeName.create("io.helidon.service.registry.Service.NamedByType");
    static final TypeName SERVICE_SINGLETON = TypeName.create("io.helidon.service.registry.Service.Singleton");


}
