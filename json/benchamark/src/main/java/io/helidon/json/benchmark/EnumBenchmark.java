package io.helidon.json.benchmark;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import io.helidon.json.binding.JsonBinding;
import io.helidon.service.registry.Services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.blackbird.BlackbirdModule;
import com.jsoniter.JsonIterator;
import com.jsoniter.spi.DecodingMode;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
//@Fork(value = 2, jvmArgs = "--add-opens=java.base/java.lang=ALL-UNNAMED")
public class EnumBenchmark {

    static final String ENUM_VALUE = "[\"VALUE1\",\"VALUE1\",\"VALUE2\",\"VALUE3\"]";

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);
    private static final ObjectMapper BASIC_JACKSON = new ObjectMapper();
    private static final ObjectMapper JACKSON_BLACKBIRD = new ObjectMapper().registerModule(new BlackbirdModule());

    static {
        //To enable field name processing as hashes
        JsonIterator.setMode(DecodingMode.DYNAMIC_MODE_AND_MATCH_FIELD_WITH_HASH);
    }

    public static void main(String[] args) {
        TestEnum[] deserialize = HELIDON.deserialize(ENUM_VALUE, TestEnum[].class);
        System.out.println(Arrays.toString(deserialize));
    }

    @Benchmark
    public void helidon(Blackhole bh) {
        bh.consume(HELIDON.deserialize(ENUM_VALUE, TestEnum[].class));
    }

    @Benchmark
    public void jsoniter(Blackhole bh) {
        bh.consume(JsonIterator.deserialize(ENUM_VALUE, TestEnum[].class));
    }

    @Benchmark
    public void jacksonBlackbird(Blackhole bh) throws JsonProcessingException {
        bh.consume(JACKSON_BLACKBIRD.readValue(ENUM_VALUE, TestEnum[].class));
    }

    @Benchmark
    public void jackson(Blackhole bh) throws JsonProcessingException {
        bh.consume(BASIC_JACKSON.readValue(ENUM_VALUE, TestEnum[].class));
    }

    public static enum TestEnum {
        VALUE1, VALUE2, VALUE3
    }

}
