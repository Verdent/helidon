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
 * {@link io.helidon.security.EndpointConfig}. Only one outbound strategy may be enabled per policy.
 */
@Prototype.Blueprint(decorator = OidcOutboundPolicyConfigDecorator.class)
@Prototype.Configured
interface OidcOutboundPolicyConfigBlueprint {
    /**
     * Whether Token Propagation is enabled for this outbound policy.
     * Defaults to {@code false}.
     * <p>
     * Propagation prepares the Authorization header only. Direct access with certificate-bound tokens requires matching
     * mutual-TLS proof on the application's downstream connection; tenant {@code webclient.tls} does not configure it.
     * The downstream client must supply the matching certificate and private-key proof when propagating
     * certificate-bound access tokens; the tenant WebClient is used for Authorization Server calls, not downstream calls.
     *
     * @return whether Token Propagation is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean tokenPropagationEnabled();

    /**
     * Whether Client Credentials Grant is enabled for this outbound policy; mutual TLS methods require enabled tenant
     * {@code webclient.tls} and an HTTPS Token Endpoint or HTTPS well-known metadata.
     * Defaults to {@code false}.
     * <p>
     * Configured outbound targets validate prerequisites for each enabled tenant at startup. Endpoint-level policies
     * validate them when used: {@code client-id}, client authentication other than {@code NONE}, a
     * {@code client-secret} for client-secret based authentication, {@code client-assertion.jwk} for
     * {@code PRIVATE_KEY_JWT} or enabled tenant {@code webclient.tls} with private key plus certificate chain, an SSL
     * context, or a custom TLS manager for mutual TLS authentication, and either {@code endpoints.token-endpoint-uri} or
     * well-known metadata.
     *
     * @return whether Client Credentials Grant is enabled
     */
    @Description("Whether Client Credentials Grant is enabled for this outbound policy; mutual TLS methods require "
            + "enabled tenant webclient.tls and an HTTPS Token Endpoint or HTTPS well-known metadata.")
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean clientCredentialsGrantEnabled();

    /**
     * Access-token scopes requested by Client Credentials Grant for this outbound policy.
     * <p>
     * This value is used only when {@code client-credentials-grant-enabled} is enabled on the same policy.
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
     * This value is used only when {@code client-credentials-grant-enabled} is enabled on the same policy.
     * When configured, each value is sent as a separate OAuth {@code resource} token endpoint form parameter.
     *
     * @return Client Credentials Grant resource indicators
     */
    @Description("Resource indicators requested by Client Credentials Grant for this outbound policy.")
    @Option.Configured
    @Option.Singular("clientCredentialsResource")
    List<String> clientCredentialsResources();

    /**
     * Whether RFC 8693 Token Exchange is enabled for this outbound policy.
     * Defaults to {@code false}.
     * <p>
     * Token Exchange uses the current subject {@code TokenCredential} as {@code subject_token}, asks the tenant Token
     * Endpoint for a downstream access token, and attaches the exchanged token as
     * {@code Authorization: Bearer <access-token>}. The first implementation supports only access-token-to-Bearer
     * access-token exchange.
     *
     * @return whether Token Exchange is enabled
     */
    @Description("Whether RFC 8693 Token Exchange is enabled for this outbound policy.")
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean tokenExchangeEnabled();

    /**
     * Access-token scopes requested by Token Exchange for this outbound policy.
     * <p>
     * This value is used only when {@code token-exchange-enabled} is enabled on the same policy. When
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
     * This value is used only when {@code token-exchange-enabled} is enabled on the same policy. When
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
     * This value is used only when {@code token-exchange-enabled} is enabled on the same policy. When
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
     * This value is used only when {@code token-propagation-enabled} is enabled on the same policy.
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
