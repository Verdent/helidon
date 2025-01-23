module helidon.json.binding {

    requires transitive helidon.json.parser;
    requires transitive io.helidon.service.registry;

    requires io.helidon.common.config;
    requires jdk.jdi;

    exports io.helidon.json.binding;
    exports io.helidon.json.binding.converters;
    exports io.helidon.json.binding.factories;
}