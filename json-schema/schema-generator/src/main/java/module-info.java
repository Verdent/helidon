module schema.generator {
    requires io.helidon.codegen;
    requires io.helidon.common.types;
    requires io.helidon.builder.api;
    requires io.helidon.service.registry;
    requires io.helidon.jsonschema.schema;

    exports io.helidon.jsonschema.generator;

    provides io.helidon.codegen.spi.CodegenExtensionProvider
            with io.helidon.jsonschema.generator.SchemaCodegenProvider;
}
