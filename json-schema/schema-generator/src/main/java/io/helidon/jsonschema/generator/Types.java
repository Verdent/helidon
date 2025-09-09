package io.helidon.jsonschema.generator;

import java.math.BigDecimal;
import java.math.BigInteger;

import io.helidon.common.types.TypeName;

class Types {

    //Common annotations
    static final TypeName JSON_SCHEMA_SCHEMA = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Schema");
    static final TypeName JSON_SCHEMA_TITLE = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Title");
    static final TypeName JSON_SCHEMA_DESCRIPTION = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Description");
    static final TypeName JSON_SCHEMA_REQUIRED = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Required");
    static final TypeName JSON_SCHEMA_PROVIDER = TypeName.create("io.helidon.jsonschema.schema.JsonSchemaProvider");
    static final TypeName JSON_SCHEMA_DO_NOT_INSPECT = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.DoNotInspect");
    static final TypeName JSON_SCHEMA_IGNORE = TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Ignore");

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
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Object.MinProperties");
    static final TypeName JSON_SCHEMA_OBJECT_MAX_PROPERTIES =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Object.MaxProperties");

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

    //Array annotations
    static final TypeName JSON_SCHEMA_ARRAY_MAX_ITEMS =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Array.MaxItems");
    static final TypeName JSON_SCHEMA_ARRAY_MIN_ITEMS =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Array.MinItems");
    static final TypeName JSON_SCHEMA_ARRAY_MAX_CONTAINS =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Array.MaxContains");
    static final TypeName JSON_SCHEMA_ARRAY_MIN_CONTAINS =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Array.MinContains");
    static final TypeName JSON_SCHEMA_ARRAY_UNIQUE_ITEMS =
            TypeName.create("io.helidon.jsonschema.schema.JsonSchema.Array.UniqueItems");

    //Schema related types
    static final TypeName SCHEMA = TypeName.create("io.helidon.jsonschema.schema.Schema");

    //Random types
    static final TypeName LAZY_VALUE = TypeName.create("io.helidon.common.LazyValue");
    static final TypeName LAZY_VALUE_SCHEMA = TypeName.builder(Types.LAZY_VALUE)
            .addTypeArgument(Types.SCHEMA)
            .build();
    static final TypeName BIG_DECIMAL =  TypeName.create(BigDecimal.class);
    static final TypeName BIG_INTEGER =  TypeName.create(BigInteger.class);
    static final TypeName NUMBER =  TypeName.create(Number.class);
    static final TypeName JSONB_TRANSIENT =  TypeName.create("jakarta.json.bind.annotation.JsonbTransient");

    //Service registry related annotations
    static final TypeName SERVICE_NAMED_BY_TYPE = TypeName.create("io.helidon.service.registry.Service.NamedByType");
    static final TypeName SERVICE_SINGLETON = TypeName.create("io.helidon.service.registry.Service.Singleton");


}
