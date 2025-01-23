package io.helidon.json.benchmark;

import java.util.concurrent.TimeUnit;

import io.helidon.json.binding.JsonBinding;

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
//@Fork(0)
public class HelidonJsonBenchmark {

    private static final String JSON = "{\"fieldTwo\":2147,"
            + "\"fieldOne\":\"Hello\","
            + "\"fieldThree\":\"World\","
            + "\"fieldFour\":   null ,"
            + "\"fieldFive\":\"1234\", "
            + "\"otherBean\":{"
            + "\"otherString\":\"Hello there!\""
            + "}}";

    @Benchmark
    public void simpleObject(Blackhole bh) {
        bh.consume(JsonBinding.deserialize(JSON, MyJavaBean.class));
    }

}
