package io.helidon.json.benchmark;

import java.io.IOException;
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
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

import static io.helidon.json.benchmark.JsonTemplates.CLASS_WITH_LIST;
import static io.helidon.json.benchmark.JsonTemplates.MY_JAVA_BEAN_WITH_OTHER_BEAN;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(2)
public class HelidonJsonBenchmark {

    static {
        JsonIterator.setMode(DecodingMode.DYNAMIC_MODE_AND_MATCH_FIELD_WITH_HASH);
    }

    private ObjectMapper mapper = new ObjectMapper();
    private ObjectMapper blackbird = new ObjectMapper();
    {
        blackbird.registerModule(new BlackbirdModule());
    }

//    private io.micronaut.serde.ObjectMapper micronaut;
//
//    @Setup
//    public void setup() throws Exception {
//        ApplicationContext context = ApplicationContext.run();
//        micronaut = context.getBean(io.micronaut.serde.ObjectMapper.class);
//    }
//
//    public static void main(String[] args) {
//        ApplicationContext context = ApplicationContext.run();
//        context.getBean(io.micronaut.serde.ObjectMapper.class);
//    }

//    @Benchmark
//    public void helidon(Blackhole bh) {
//        bh.consume(JsonBinding.deserialize(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
//    }
    //
//        @Benchmark
//        public void jsoniter(Blackhole bh) {
//            bh.consume(JsonIterator.deserialize(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
//        }
//    @Benchmark
//    public void jacksonBlackbird(Blackhole bh) throws JsonProcessingException {
//        bh.consume(blackbird.readValue(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
//    }
//
//    @Benchmark
//    public void jackson(Blackhole bh) throws JsonProcessingException {
//        bh.consume(mapper.readValue(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
//    }

//    @Benchmark
//    public void micronaut(Blackhole bh) throws IOException {
//        bh.consume(micronaut.readValue(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
//    }

//        @Benchmark
//        public void helidon(Blackhole bh) {
//            bh.consume(JsonBinding.deserialize(CLASS_WITH_LIST, ClassWithList.class));
//        }
//
//        @Benchmark
//        public void jsoniter(Blackhole bh) {
//            bh.consume(JsonIterator.deserialize(CLASS_WITH_LIST, ClassWithList.class));
//        }
//    @Benchmark
//    public void jacksonBlackbird(Blackhole bh) throws JsonProcessingException {
//        bh.consume(blackbird.readValue(CLASS_WITH_LIST, ClassWithList.class));
//    }
//
//    @Benchmark
//    public void jackson(Blackhole bh) throws JsonProcessingException {
//        bh.consume(mapper.readValue(CLASS_WITH_LIST, ClassWithList.class));
//    }

    //    @Benchmark
    //    public void helidon(Blackhole bh) {
    //        bh.consume(JsonBinding.deserialize("12345", long.class));
    //    }
    //
    //
    //    @Benchmark
    //    public void jsoniter(Blackhole bh) {
    //        bh.consume(JsonIterator.deserialize("12345", long.class));
    //    }

}
