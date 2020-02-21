/*
 * Copyright (c) 2020 Oracle and/or its affiliates.
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
package io.helidon.webclient.metrics;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.helidon.webclient.ClientServiceRequest;

import org.eclipse.microprofile.metrics.Metadata;
import org.eclipse.microprofile.metrics.Meter;
import org.eclipse.microprofile.metrics.MetricType;

/**
 * Client metric meter for all requests.
 */
public class ClientMeter extends ClientMetric {

    ClientMeter(Builder builder) {
        super(builder);
    }

    @Override
    MetricType metricType() {
        return MetricType.METERED;
    }

    @Override
    public CompletionStage<ClientServiceRequest> request(ClientServiceRequest request) {
        request.whenComplete()
                .thenAccept(response -> {
                    if (handlesMethod(request.method())) {
                        if (measureSuccess() && response.status().code() < 400) {
                            updateMeter(createMetadata(request, response));
                        } else if (measureErrors() && response.status().code() >= 400) {
                            updateMeter(createMetadata(request, response));
                        }
                    }
                })
                .exceptionally(throwable -> {
                    if (measureErrors()) {
                        updateMeter(createMetadata(request, null));
                    }
                    return null;
                });

        return CompletableFuture.completedFuture(request);
    }

    private void updateMeter(Metadata metadata) {
        Meter meter = metricRegistry().meter(metadata);
        meter.mark();
    }
}
