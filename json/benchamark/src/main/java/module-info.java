module helidon.json.benchmark {
    requires jmh.core;
    requires jsoniter;
    requires com.fasterxml.jackson.annotation;
    requires helidon.json.binding;

    exports io.helidon.json.benchmark;
}