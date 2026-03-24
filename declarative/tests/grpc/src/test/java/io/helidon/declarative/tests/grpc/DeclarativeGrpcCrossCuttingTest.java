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

import io.helidon.grpc.api.RpcClient;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.service.registry.Lookup;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.ServiceRegistry;
import io.helidon.webclient.http1.Http1Client;
import io.helidon.webserver.testing.junit5.ServerTest;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.sdk.trace.data.SpanData;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@ServerTest
class DeclarativeGrpcCrossCuttingTest {
    private final Http1Client httpClient;
    private final ServiceRegistry registry;
    private final TestSpanExporter exporter;

    DeclarativeGrpcCrossCuttingTest(Http1Client httpClient,
                                    ServiceRegistry registry,
                                    TestTracerFactory tracerFactory) {
        this.httpClient = httpClient;
        this.registry = registry;
        this.exporter = tracerFactory.exporter();
    }

    @BeforeEach
    void beforeEach() {
        exporter.clear();
    }

    @Test
    void testMetricsAndTracingOnGrpcEntryPoint() {
        TextServiceClient typedClient = typedClient();
        int initialCounter = counterValue();

        TextMessages.TextMessage response = typedClient.upper(message("hello"));
        assertThat(response.getText(), is("HELLO"));

        SpanData tracedMethod = exporter.spanNamed("grpc.upper");
        assertThat(tracedMethod.getKind(), is(SpanKind.SERVER));
        assertAttribute(tracedMethod, "transport", "grpc");

        assertThat(counterValue(), is(initialCounter + 1));
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

    private int counterValue() {
        var metricsResponse = httpClient.get("/observe/metrics")
                .header(HeaderValues.ACCEPT_JSON)
                .request(JsonObject.class);

        assertThat(metricsResponse.status(), is(Status.OK_200));

        JsonObject applicationMetrics = metricsResponse.entity().getJsonObject("application");
        if (applicationMetrics == null) {
            return 0;
        }

        JsonNumber counter = applicationMetrics.getJsonNumber("grpc-upper-count");
        return counter == null ? 0 : counter.intValue();
    }

    private static void assertAttribute(SpanData spanData, String key, String expectedValue) {
        String actualValue = spanData.getAttributes().get(AttributeKey.stringKey(key));
        assertThat(actualValue, is(expectedValue));
    }
}
