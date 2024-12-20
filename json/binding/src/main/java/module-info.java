module helidon.json.binding {
    requires transitive io.helidon.common.types;

    requires helidon.json.parser;
    requires io.helidon.builder.api;
    requires io.helidon.common.config;

    exports io.helidon.json.binding;
    exports io.helidon.json.binding.converters;
    exports io.helidon.json.binding.spi;

    provides io.helidon.json.binding.spi.JsonComponentProvider
            with io.helidon.json.binding.DefaultComponentProvider;
}