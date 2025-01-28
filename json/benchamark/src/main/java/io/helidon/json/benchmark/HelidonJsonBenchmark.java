package io.helidon.json.benchmark;

import java.util.concurrent.TimeUnit;

import io.helidon.json.binding.JsonBinding;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

import static io.helidon.json.benchmark.JsonTemplates.MY_JAVA_BEAN_WITH_OTHER_BEAN;
import static io.helidon.json.benchmark.JsonTemplates.CLASS_WITH_LIST;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
//@Fork(0)
public class HelidonJsonBenchmark {

    @Benchmark
    public void javaBeanWithOtherBean(Blackhole bh) {
        bh.consume(JsonBinding.deserialize(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
    }

    @Benchmark
    public void classWithList(Blackhole bh) {
        bh.consume(JsonBinding.deserialize(CLASS_WITH_LIST, ClassWithList.class));
    }

}
