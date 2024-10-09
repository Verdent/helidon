/*
 * Copyright (c) 2023, 2024 Oracle and/or its affiliates.
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

package io.helidon.webclient.http1;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.common.concurrency.limits.Limit;
import io.helidon.common.concurrency.limits.spi.LimitProvider;
import io.helidon.webclient.api.HttpClientConfig;

/**
 * HTTP/1.1. full webclient configuration.
 */
@Prototype.Configured
@Prototype.Blueprint
interface Http1ClientConfigBlueprint extends HttpClientConfig, Prototype.Factory<Http1Client> {
    /**
     * HTTP/1.1 specific configuration.
     *
     * @return protocol specific configuration
     */
    @Option.Default("create()")
    Http1ClientProtocolConfig protocolConfig();

    @Option.Configured
    Optional<Http1ConnectionCacheConfig> connectionCache();

}
