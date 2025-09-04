package io.helidon.jsonschema.schema;

import io.helidon.builder.api.Prototype;

class SchemaIntegerCustomMethods {

    @Prototype.BuilderMethod
    static void multipleOf(SchemaInteger.BuilderBase<?,?> builder, int value) {
        builder.multipleOf((long)value);
    }

    @Prototype.BuilderMethod
    static void minimum(SchemaInteger.BuilderBase<?,?> builder, int value) {
        builder.minimum((long)value);
    }

    @Prototype.BuilderMethod
    static void maximum(SchemaInteger.BuilderBase<?,?> builder, int value) {
        builder.maximum((long)value);
    }

    @Prototype.BuilderMethod
    static void exclusiveMaximum(SchemaInteger.BuilderBase<?,?> builder, int value) {
        builder.exclusiveMaximum((long)value);
    }

    @Prototype.BuilderMethod
    static void exclusiveMinimum(SchemaInteger.BuilderBase<?,?> builder, int value) {
        builder.exclusiveMinimum((long)value);
    }

}
