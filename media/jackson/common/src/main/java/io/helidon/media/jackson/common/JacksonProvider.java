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

package io.helidon.media.jackson.common;

import io.helidon.config.Config;
import io.helidon.media.common.spi.MediaService;
import io.helidon.media.common.spi.MediaServiceProvider;

/**
 * Jackson support SPI provider.
 */
public class JacksonProvider implements MediaServiceProvider {

    private static final String JACKSON = "jackson";

    @Override
    public MediaService create(String type, Config config) {
        return JacksonSupport.create();
    }

    @Override
    public String type() {
        return JACKSON;
    }
}
