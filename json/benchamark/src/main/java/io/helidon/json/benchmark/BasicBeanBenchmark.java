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
@Fork(value = 2, jvmArgs = "--add-opens=java.base/java.lang=ALL-UNNAMED")
public class BasicBeanBenchmark {

    static final String MY_JAVA_BEAN_WITH_OTHER_BEAN = "{"
            + "\"fieldTwo\":2147,"
            + "\"fieldOne\":\"Hello\","
            + "\"fieldThree\":\"World\","
            + "\"fieldFour\":null,"
            + "\"fieldFive\":\"1234\","
            + "\"fieldSix\":4567,"
            + "\"otherBean\":{"
            + "\"otherString\":\"Hello there!\""
            + "}}";

    private static final JsonBinding HELIDON = JsonBinding.create();
    private static final ObjectMapper BASIC_JACKSON = new ObjectMapper();
    private static final ObjectMapper JACKSON_BLACKBIRD = new ObjectMapper().registerModule(new BlackbirdModule());

    static {
        //To enable field name processing as hashes
        JsonIterator.setMode(DecodingMode.DYNAMIC_MODE_AND_MATCH_FIELD_WITH_HASH);
    }

    public static void main(String[] args) {
        MyJavaBean deserialize = HELIDON.deserialize(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class);
        System.out.println();
    }

    @Benchmark
    public void helidon(Blackhole bh) {
        bh.consume(HELIDON.deserialize(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
    }

    @Benchmark
    public void jsoniter(Blackhole bh) {
        bh.consume(JsonIterator.deserialize(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
    }

    @Benchmark
    public void jacksonBlackbird(Blackhole bh) throws JsonProcessingException {
        bh.consume(JACKSON_BLACKBIRD.readValue(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
    }

    @Benchmark
    public void jackson(Blackhole bh) throws JsonProcessingException {
        bh.consume(BASIC_JACKSON.readValue(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
    }

}
