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
import java.util.Optional;

import io.helidon.builder.api.Description;
import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * OIDC-specific outbound security policy for a configured target or an individual request.
 * Use this as a custom object on an {@link io.helidon.security.providers.common.OutboundTarget} or
 * {@link io.helidon.security.EndpointConfig}. Each policy selects at most one outbound strategy.
 */
@Prototype.Blueprint(decorator = OidcOutboundPolicyConfigDecorator.class)
@Prototype.Configured
interface OidcOutboundPolicyConfigBlueprint {
    /**
     * Outbound strategy for this policy. Defaults to {@link OidcOutboundStrategy#NONE NONE}.
     * <p>
     * {@code NONE} selects no strategy at this level. For an endpoint policy, a matching outbound target policy may
     * still apply. Token Propagation prepares the Authorization header only; propagating certificate-bound access tokens
     * also requires the downstream client to supply matching mutual-TLS certificate and private-key proof. Tenant
     * {@code webclient.tls} configures Authorization Server calls, not the downstream connection.
     *
     * @return selected outbound strategy
     */
    @Option.Configured
    @Option.Default("NONE")
    OidcOutboundStrategy strategy();

    /**
     * Access-token scopes requested by Client Credentials Grant for this outbound policy.
     * <p>
     * This value is used only when {@link #strategy()} selects {@code CLIENT_CREDENTIALS}.
     * When configured, the scopes are serialized as a single OAuth {@code scope} token endpoint form parameter.
     *
     * @return Client Credentials Grant scopes
     */
    @Description("Access-token scopes requested by Client Credentials Grant for this outbound policy.")
    @Option.Configured
    @Option.Singular("clientCredentialsScope")
    List<String> clientCredentialsScopes();

    /**
     * Resource indicators requested by Client Credentials Grant for this outbound policy.
     * <p>
     * This value is used only when {@link #strategy()} selects {@code CLIENT_CREDENTIALS}.
     * When configured, each value is sent as a separate OAuth {@code resource} token endpoint form parameter.
     *
     * @return Client Credentials Grant resource indicators
     */
    @Description("Resource indicators requested by Client Credentials Grant for this outbound policy.")
    @Option.Configured
    @Option.Singular("clientCredentialsResource")
    List<String> clientCredentialsResources();

    /**
     * Access-token scopes requested by Token Exchange for this outbound policy.
     * <p>
     * This value is used only when {@link #strategy()} selects {@code TOKEN_EXCHANGE}. When
     * configured, the scopes are serialized as a single OAuth {@code scope} token endpoint form parameter.
     *
     * @return Token Exchange scopes
     */
    @Description("Access-token scopes requested by Token Exchange for this outbound policy.")
    @Option.Configured
    @Option.Singular("tokenExchangeScope")
    List<String> tokenExchangeScopes();

    /**
     * Target resource requested by Token Exchange for this outbound policy.
     * <p>
     * This value is used only when {@link #strategy()} selects {@code TOKEN_EXCHANGE}. When
     * configured, it is sent as the RFC 8693 {@code resource} token endpoint form parameter.
     *
     * @return Token Exchange resource
     */
    @Description("Target resource requested by Token Exchange for this outbound policy.")
    @Option.Configured
    Optional<String> tokenExchangeResource();

    /**
     * Target audience requested by Token Exchange for this outbound policy.
     * <p>
     * This value is used only when {@link #strategy()} selects {@code TOKEN_EXCHANGE}. When
     * configured, it is sent as the RFC 8693 {@code audience} token endpoint form parameter. This is separate from
     * {@link #audience()}, which is a local Token Propagation audience check.
     *
     * @return Token Exchange audience
     */
    @Description("Target audience requested by Token Exchange for this outbound policy.")
    @Option.Configured
    Optional<String> tokenExchangeAudience();

    /**
     * Expected access-token audience for Token Propagation to this outbound policy.
     * <p>
     * This value is used only when {@link #strategy()} selects {@code TOKEN_PROPAGATION}.
     *
     * @return expected audience
     */
    @Option.Configured
    Optional<String> audience();

    /**
     * Whether Token Propagation audience validation is enabled for this outbound policy.
     * <p>
     * Defaults to {@code true}. When enabled, {@link #audience()} must be configured and the current JWT or
     * introspection-backed access token must contain that audience value before it is propagated. Disabling this option
     * allows raw or opaque token propagation without a local audience check and should be used only for testing, local
     * development, or legacy deployments where audience claims are not available to this provider.
     *
     * @return whether Token Propagation audience validation is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean audienceValidationEnabled();
}
