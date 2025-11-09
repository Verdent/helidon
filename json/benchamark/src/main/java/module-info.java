module helidon.json.benchmark {
    requires jmh.core;
    requires jsoniter;
    requires com.fasterxml.jackson.annotation;
    requires io.helidon.json.binding;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.module.blackbird;

    exports io.helidon.json.benchmark;
}