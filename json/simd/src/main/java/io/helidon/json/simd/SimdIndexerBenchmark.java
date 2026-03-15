package io.helidon.json.simd;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

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
@Fork(value = 2, jvmArgs = "--add-modules=jdk.incubator.vector")
public class SimdIndexerBenchmark {

    private byte[] templateBytes;

    @Setup(Level.Trial)
    public void setup() {

        try (InputStream is = SimdIndexerBenchmark.class.getResourceAsStream("/twitter.json")) {
            templateBytes = is.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Benchmark
    public int helidon(Blackhole bh) {
        return Main34.createTape(templateBytes, Main34.newWorkspace());
    }

    @Benchmark
    public BitIndexes simdJsonparser(Blackhole bh) {
        BitIndexes bitIndexes = new BitIndexes(templateBytes.length);
        new StructuralIndexer(bitIndexes).index(templateBytes, templateBytes.length);
        return bitIndexes;
    }


}
