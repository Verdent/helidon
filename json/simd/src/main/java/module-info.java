module io.helidon.json.simd {
    requires io.helidon.common.buffers;
    requires io.helidon.json;
    requires jdk.incubator.vector;
    requires jmh.core;

    exports io.helidon.json.simd;
}
