/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
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

package io.helidon.declarative.tests.grpc;

import java.util.List;
import java.util.stream.Stream;

import io.helidon.metrics.api.Counter;
import io.helidon.metrics.api.MeterRegistry;
import io.helidon.service.registry.Lookup;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.ServiceRegistry;
import io.helidon.webclient.grpc.RpcClient;
import io.helidon.webserver.testing.junit5.ServerTest;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.sdk.trace.data.SpanData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@ExtendWith(GrpcTestEnvironmentExtension.class)
@ServerTest
class DeclarativeGrpcCrossCuttingTest {
    private final MeterRegistry meterRegistry;
    private final ServiceRegistry registry;
    private final TestSpanExporter exporter;

    DeclarativeGrpcCrossCuttingTest(ServiceRegistry registry,
                                    TestTracerFactory tracerFactory) {
        this.registry = registry;
        this.meterRegistry = registry.get(MeterRegistry.class);
        this.exporter = tracerFactory.exporter();
    }

    @BeforeEach
    void beforeEach() {
        exporter.clear();
    }

    @Test
    void testMetricsAndTracingOnGrpcEntryPoint() {
        TextServiceClient typedClient = typedClient();
        long initialCounter = counterValue("grpc-upper-count");

        TextMessages.TextMessage response = typedClient.upper(message("hello"));
        assertThat(response.getText(), is("HELLO"));

        SpanData tracedMethod = exporter.spanNamed("grpc.upper");
        assertThat(tracedMethod.getKind(), is(SpanKind.SERVER));
        assertAttribute(tracedMethod, "transport", "grpc");

        assertThat(counterValue("grpc-upper-count"), is(initialCounter + 1));
    }

    @Test
    void testMetricsAndTracingOnClientStreamingEntryPoint() {
        TextServiceClient typedClient = typedClient();
        long initialCounter = counterValue("grpc-join-count");

        TextMessages.TextMessage response = typedClient.join(Stream.of(message("hello"), message("world")));
        assertThat(response.getText(), is("hello world"));

        SpanData tracedMethod = exporter.spanNamed("grpc.join");
        assertThat(tracedMethod.getKind(), is(SpanKind.SERVER));
        assertAttribute(tracedMethod, "transport", "grpc");

        assertThat(counterValue("grpc-join-count"), is(initialCounter + 1));
    }

    private TextServiceClient typedClient() {
        return registry.get(Lookup.builder()
                                    .addContract(TextServiceClient.class)
                                    .addQualifier(Qualifier.create(RpcClient.Client.class))
                                    .build());
    }

    private static TextMessages.TextMessage message(String text) {
        return TextMessages.TextMessage.newBuilder()
                .setText(text)
                .build();
    }

    private long counterValue(String metricName) {
        return meterRegistry.counter(metricName, List.of())
                .map(Counter::count)
                .orElse(0L);
    }

    private static void assertAttribute(SpanData spanData, String key, String expectedValue) {
        String actualValue = spanData.getAttributes().get(AttributeKey.stringKey(key));
        assertThat(actualValue, is(expectedValue));
    }
}
