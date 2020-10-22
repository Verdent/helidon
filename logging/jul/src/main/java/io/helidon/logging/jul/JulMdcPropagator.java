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
package io.helidon.logging.jul;

import java.util.Map;

import io.helidon.common.context.spi.DataPropagationProvider;

/**
 * This is propagator of JUL MDC values between different threads.
 */
public class JulMdcPropagator implements DataPropagationProvider<Map<String, String>> {

    @Override
    public Map<String, String> data() {
        return JulMdc.properties();
    }

    @Override
    public void propagateData(Map<String, String> data) {
        JulMdc.properties(data);
    }

    @Override
    public void clearData() {
        JulMdc.clear();
    }

}