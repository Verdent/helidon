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

import io.helidon.logging.spi.MdcProvider;

/**
 * Provider for setting MDC values to the Java Util Logging MDC support.
 */
public class JulMdcProvider implements MdcProvider {
    @Override
    public void put(String key, Object value) {
        JulMdc.put(key, String.valueOf(value));
    }

    @Override
    public void remove(String key) {
        JulMdc.remove(key);
    }

    @Override
    public void clear() {
        JulMdc.clear();
    }

    @Override
    public String get(String key) {
        return JulMdc.get(key);
    }
}
