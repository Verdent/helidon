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

import java.time.Duration;
import java.util.Map;
import java.util.function.Supplier;

import io.helidon.service.registry.Service;
import io.helidon.tracing.Tracer;
import io.helidon.tracing.providers.opentelemetry.HelidonOpenTelemetry;

import io.opentelemetry.api.baggage.propagation.W3CBaggagePropagator;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;
import io.opentelemetry.semconv.ServiceAttributes;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.context.propagation.TextMapPropagator;

@Service.Singleton
class TestTracerFactory implements Supplier<Tracer> {
    private final TestSpanExporter exporter = new TestSpanExporter();
    private final OpenTelemetrySdk openTelemetry;
    private final Tracer tracer;

    public TestTracerFactory() {
        SdkTracerProvider tracerProvider = SdkTracerProvider.builder()
                .setResource(Resource.getDefault().merge(Resource.create(Attributes.of(ServiceAttributes.SERVICE_NAME,
                                                                                       "declarative-grpc-test"))))
                .addSpanProcessor(BatchSpanProcessor.builder(exporter)
                        .setScheduleDelay(Duration.ofMillis(100))
                        .build())
                .build();

        openTelemetry = OpenTelemetrySdk.builder()
                .setTracerProvider(tracerProvider)
                .setPropagators(ContextPropagators.create(TextMapPropagator.composite(
                        W3CTraceContextPropagator.getInstance(),
                        W3CBaggagePropagator.getInstance())))
                .build();

        tracer = HelidonOpenTelemetry.create(openTelemetry,
                                             openTelemetry.getTracer("declarative-grpc-test"),
                                             Map.of());
    }

    @Override
    public Tracer get() {
        return tracer;
    }

    @Service.PreDestroy
    public void shutdown() {
        openTelemetry.close();
        exporter.close();
    }

    TestSpanExporter exporter() {
        return exporter;
    }
}
