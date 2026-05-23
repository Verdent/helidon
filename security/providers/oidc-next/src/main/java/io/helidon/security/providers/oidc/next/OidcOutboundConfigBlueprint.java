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
 * Outbound OIDC/OAuth configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcOutboundConfigBlueprint {
    /**
     * Whether outbound Token Propagation is enabled.
     *
     * @return whether Token Propagation is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean tokenPropagationEnabled();

    /**
     * Whether outbound Client Credentials Grant is enabled.
     * <p>
     * Client Credentials Grant requires a confidential client: {@code client-id}, client authentication other than
     * {@code NONE}, a {@code client-secret} for client-secret based authentication, and either
     * {@code endpoints.token-endpoint-uri} or well-known metadata.
     *
     * @return whether Client Credentials Grant is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean clientCredentialsGrantEnabled();
}
