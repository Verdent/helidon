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

import java.util.List;

import io.helidon.builder.api.Description;
import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.security.providers.common.OutboundTarget;

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
     * Whether outbound Client Credentials Grant is enabled; mutual TLS methods require enabled tenant
     * {@code webclient.tls} and an HTTPS Token Endpoint or HTTPS well-known metadata.
     * <p>
     * Client Credentials Grant requires a confidential client: {@code client-id}, client authentication other than
     * {@code NONE}, a {@code client-secret} for client-secret based authentication, and either
     * {@code client-assertion.jwk} for {@code PRIVATE_KEY_JWT} or enabled tenant {@code webclient.tls} with private key
     * plus certificate chain, an SSL context, or a custom TLS manager for mutual TLS authentication, and either
     * {@code endpoints.token-endpoint-uri} or well-known metadata.
     *
     * @return whether Client Credentials Grant is enabled
     */
    @Description("Whether outbound Client Credentials Grant is enabled; mutual TLS methods require enabled tenant "
            + "webclient.tls and an HTTPS Token Endpoint or HTTPS well-known metadata.")
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean clientCredentialsGrantEnabled();

    /**
     * Outbound targets that may receive Token Propagation or Client Credentials Grant tokens for this tenant.
     * <p>
     * Each target uses Helidon's common {@link OutboundTarget} matching keys, and can include OIDC-specific target
     * options from {@link OidcOutboundTargetConfig}, such as {@code token-propagation-enabled},
     * {@code client-credentials-grant-enabled}, and {@code audience}.
     *
     * @return outbound targets for this tenant
     */
    @Option.Configured
    @Option.Singular("target")
    List<OutboundTarget> targets();
}
