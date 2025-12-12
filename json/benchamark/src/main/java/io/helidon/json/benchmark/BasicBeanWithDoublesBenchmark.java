/*
 * Copyright (c) 2025 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.json.benchmark;

import java.util.concurrent.TimeUnit;

import io.helidon.json.binding.JsonBinding;
import io.helidon.service.registry.Services;

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
public class BasicBeanWithDoublesBenchmark {

    static final String JSON_WITH_DOUBLES = "{"
            + "\"one\":123.45678,"
            + "\"two\":123.456987,"
            + "\"three\":123.456111"
            + "}";

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);
    private static final ObjectMapper BASIC_JACKSON = new ObjectMapper();
    private static final ObjectMapper JACKSON_BLACKBIRD = new ObjectMapper().registerModule(new BlackbirdModule());

    static {
        //To enable field name processing as hashes
        JsonIterator.setMode(DecodingMode.DYNAMIC_MODE_AND_MATCH_FIELD_WITH_HASH);
    }

    public static void main(String[] args) {
        BeanWithDoubles deserialize = HELIDON.deserialize(JSON_WITH_DOUBLES, BeanWithDoubles.class);
        System.out.println(deserialize);
    }

    @Benchmark
    public void helidon(Blackhole bh) {
        bh.consume(HELIDON.deserialize(JSON_WITH_DOUBLES, BeanWithDoubles.class));
    }

    @Benchmark
    public void jsoniter(Blackhole bh) {
        bh.consume(JsonIterator.deserialize(JSON_WITH_DOUBLES, BeanWithDoubles.class));
    }

//    @Benchmark
//    public void jacksonBlackbird(Blackhole bh) throws JsonProcessingException {
//        bh.consume(JACKSON_BLACKBIRD.readValue(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
//    }
//
//    @Benchmark
//    public void jackson(Blackhole bh) throws JsonProcessingException {
//        bh.consume(BASIC_JACKSON.readValue(MY_JAVA_BEAN_WITH_OTHER_BEAN, MyJavaBean.class));
//    }

}
