package io.helidon.json.benchmark;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import io.helidon.json.binding.JsonBinding;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.blackbird.BlackbirdModule;
import com.jsoniter.JsonIterator;
import com.jsoniter.output.EncodingMode;
import com.jsoniter.output.JsonStream;
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

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(value = 2, jvmArgs = "--add-opens=java.base/java.lang=ALL-UNNAMED")
public class BasicBeanStreamBenchmark {

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
        JsonStream.setMode(EncodingMode.DYNAMIC_MODE);
    }

    private ByteArrayInputStream stream;

    @Setup(Level.Invocation)
    public void setup() {
        stream = new ByteArrayInputStream(MY_JAVA_BEAN_WITH_OTHER_BEAN.getBytes(StandardCharsets.UTF_8));
    }

    @Benchmark
    public void helidon(Blackhole bh) {
        bh.consume(HELIDON.deserialize(stream, MyJavaBean.class));
    }

    @Benchmark
    public void jsoniter(Blackhole bh) throws IOException {
        bh.consume(JsonIterator.parse(stream, 8000).read(MyJavaBean.class));
    }

    @Benchmark
    public void jacksonBlackbird(Blackhole bh) throws IOException {
        bh.consume(JACKSON_BLACKBIRD.readValue(stream, MyJavaBean.class));
    }

    @Benchmark
    public void jackson(Blackhole bh) throws IOException {
        bh.consume(BASIC_JACKSON.readValue(stream, MyJavaBean.class));
    }

}
