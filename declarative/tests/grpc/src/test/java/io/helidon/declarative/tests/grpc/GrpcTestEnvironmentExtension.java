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

import java.util.concurrent.TimeUnit;

import io.helidon.metrics.api.MetricsFactory;

import io.opentelemetry.api.GlobalOpenTelemetry;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionContext;

class GrpcTestEnvironmentExtension implements Extension, BeforeAllCallback, BeforeEachCallback, AfterAllCallback {
    private static final String OTEL_AUTO_CONFIGURE_PROP = "otel.java.global-autoconfigure.enabled";
    private static final String OTEL_SDK_DISABLED_PROP = "otel.sdk.disabled";

    private String originalOtelSdkAutoConfiguredSetting;
    private String originalOtelSdkDisabledSetting;

    @Override
    public void beforeAll(ExtensionContext context) {
        originalOtelSdkAutoConfiguredSetting = System.setProperty(OTEL_AUTO_CONFIGURE_PROP, "true");
        originalOtelSdkDisabledSetting = System.setProperty(OTEL_SDK_DISABLED_PROP, "false");
        clearGlobalState();
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        GlobalOpenTelemetry.resetForTest();
    }

    @Override
    public void afterAll(ExtensionContext context) {
        clearGlobalState();
        restoreProperty(OTEL_AUTO_CONFIGURE_PROP, originalOtelSdkAutoConfiguredSetting);
        restoreProperty(OTEL_SDK_DISABLED_PROP, originalOtelSdkDisabledSetting);
    }

    private static void clearGlobalState() {
        MetricsFactory.closeAll();
        io.micrometer.core.instrument.MeterRegistry meterRegistry = io.micrometer.core.instrument.Metrics.globalRegistry;
        meterRegistry.clear();

        int delayMs = 100;
        int iterationsRemaining = 20;
        while (iterationsRemaining > 0 && !meterRegistry.getMeters().isEmpty()) {
            iterationsRemaining--;
            try {
                TimeUnit.MILLISECONDS.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while clearing Micrometer global registry", e);
            }
        }

        GlobalOpenTelemetry.resetForTest();
    }

    private static void restoreProperty(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }
}
