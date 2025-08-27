module helidon.json.binding {

    requires transitive helidon.json.parser;
    requires transitive io.helidon.service.registry;

    requires io.helidon.config;

    exports io.helidon.json.binding;
    exports io.helidon.json.binding.converters;
    exports io.helidon.json.binding.factories;
}