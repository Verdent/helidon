package io.helidon.json.benchmark;

import java.util.concurrent.TimeUnit;

import com.jsoniter.JsonIterator;
import com.jsoniter.spi.DecodingMode;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class JsoniterBenchmark {

    private static final String JSON = "{\"fieldTwo\":2147,"
            + "\"fieldOne\":\"Hello\","
            + "\"fieldThree\":\"World\","
            + "\"fieldFour\":   null ,"
            + "\"fieldFive\":\"1234\", "
            + "\"otherBean\":{"
            + "\"otherString\":\"Hello there!\""
            + "}}";

    static {
        JsonIterator.setMode(DecodingMode.DYNAMIC_MODE_AND_MATCH_FIELD_WITH_HASH);
    }

    @Benchmark
    public void simpleObject(Blackhole bh) {
        bh.consume(JsonIterator.deserialize(JSON, MyJavaBean.class));
    }



}
