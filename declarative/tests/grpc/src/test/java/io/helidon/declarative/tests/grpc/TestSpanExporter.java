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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SpanExporter;

class TestSpanExporter implements SpanExporter {
    private static final int RETRY_COUNT = Integer.getInteger(TestSpanExporter.class.getName() + ".test.retryCount", 120);
    private static final int RETRY_DELAY_MS = Integer.getInteger(TestSpanExporter.class.getName() + ".test.retryDelayMs", 100);

    private final List<SpanData> spanData = new CopyOnWriteArrayList<>();

    @Override
    public CompletableResultCode export(Collection<SpanData> collection) {
        spanData.addAll(collection);
        return CompletableResultCode.ofSuccess();
    }

    @Override
    public CompletableResultCode flush() {
        return CompletableResultCode.ofSuccess();
    }

    @Override
    public CompletableResultCode shutdown() {
        spanData.clear();
        return CompletableResultCode.ofSuccess();
    }

    SpanData spanNamed(String spanName) {
        for (int i = 0; i < RETRY_COUNT; i++) {
            List<SpanData> snapshot = new ArrayList<>(spanData);
            for (SpanData spanDatum : snapshot) {
                if (spanName.equals(spanDatum.getName())) {
                    return spanDatum;
                }
            }

            try {
                Thread.sleep(RETRY_DELAY_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("Interrupted while waiting for span " + spanName, e);
            }
        }

        List<String> names = spanData.stream()
                .map(SpanData::getName)
                .collect(Collectors.toList());
        throw new AssertionError("Expected span " + spanName + ", found spans " + names);
    }

    void clear() {
        spanData.clear();
    }
}
