module helidon.json.codegen {
    requires io.helidon.codegen;
    requires io.helidon.common.types;
    requires io.helidon.builder.api;

    exports io.helidon.json.codegen;

    provides io.helidon.codegen.spi.CodegenExtensionProvider
            with io.helidon.json.codegen.JsonCodegenProvider;

}