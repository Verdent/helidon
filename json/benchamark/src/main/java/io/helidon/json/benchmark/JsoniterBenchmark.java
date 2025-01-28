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

import static io.helidon.json.benchmark.JsonTemplates.CLASS_WITH_LIST;
import static io.helidon.json.benchmark.JsonTemplates.MY_JAVA_BEAN_WITH_OTHER_BEAN;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class JsoniterBenchmark {

    static {
        JsonIterator.setMode(DecodingMode.DYNAMIC_MODE_AND_MATCH_FIELD_WITH_HASH);
    }

    @Benchmark
    public void javaBeanWithOtherBean(Blackhole bh) {
        bh.consume(JsonIterator.deserialize(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
    }

    @Benchmark
    public void classWithList(Blackhole bh) {
        bh.consume(JsonIterator.deserialize(CLASS_WITH_LIST, ClassWithList.class));
    }



}
