package io.helidon.json.benchmark;

import java.util.concurrent.TimeUnit;

import io.helidon.json.binding.JsonBinding;

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
@Fork(2)
public class BeanWithCollectionsBenchmark {

    static final String TEMPLATE = "{"
            + "\"list\":[123,321],"
//            + "\"list2\":[[123456, 654321], [987456321, 123456789,123456789]]"
            + "\"list2\":[[123456,654321],[123,456,789]]"
            + "}";

    private static final ObjectMapper BASIC_JACKSON = new ObjectMapper();
    private static final ObjectMapper JACKSON_BACKBIRD = new ObjectMapper().registerModule(new BlackbirdModule());

    static {
        //To enable field name processing as hashes
        JsonIterator.setMode(DecodingMode.DYNAMIC_MODE_AND_MATCH_FIELD_WITH_HASH);
    }
    
    @Benchmark
    public void helidon(Blackhole bh) {
        bh.consume(JsonBinding.deserialize(TEMPLATE, ClassWithList.class));
    }

    @Benchmark
    public void jsoniter(Blackhole bh) {
        bh.consume(JsonIterator.deserialize(TEMPLATE, ClassWithList.class));
    }

    @Benchmark
    public void jacksonBlackbird(Blackhole bh) throws JsonProcessingException {
        bh.consume(JACKSON_BACKBIRD.readValue(TEMPLATE, ClassWithList.class));
    }

    @Benchmark
    public void jackson(Blackhole bh) throws JsonProcessingException {
        bh.consume(BASIC_JACKSON.readValue(TEMPLATE, ClassWithList.class));
    }

}
