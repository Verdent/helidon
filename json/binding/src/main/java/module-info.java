module helidon.json.binding {

    requires helidon.json.parser;
    requires io.helidon.common.config;
    requires io.helidon.service.registry;
    requires jdk.jdi;

    exports io.helidon.json.binding;
    exports io.helidon.json.binding.converters;
    exports io.helidon.json.binding.factories;
}