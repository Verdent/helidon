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

package io.helidon.security.providers.oidc.next;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Bearer Token transport configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcTokenTransportConfigBlueprint {
    /**
     * Whether the Authorization request header is accepted for Bearer Token transport.
     *
     * @return whether Authorization header transport is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean authorizationHeaderEnabled();

    /**
     * Whether form-encoded body transport is accepted for Bearer Token transport.
     *
     * @return whether form-encoded body transport is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean formEncodedBodyEnabled();

    /**
     * Whether URI query parameter transport is accepted for Bearer Token transport.
     *
     * @return whether query parameter transport is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean queryParameterEnabled();
}
