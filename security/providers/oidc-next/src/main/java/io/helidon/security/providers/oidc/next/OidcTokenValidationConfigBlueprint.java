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

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Access-token validation configuration for Protected Resource Bearer Token requests and refreshed Authorization Code
 * Flow access tokens.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcTokenValidationConfigBlueprint {
    /**
     * Access-token validation method.
     *
     * @return token validation method
     */
    @Option.Configured
    Optional<OidcTokenValidationMethod> method();

    /**
     * Access-token audience expected when audience validation is required.
     * <p>
     * For JWT access-token validation, this should identify the current resource server. RFC 9068 requires JWT access
     * tokens to contain {@code aud}, and requires the resource server to validate that {@code aud} identifies itself.
     *
     * @return expected audience
     */
    @Option.Configured
    Optional<String> audience();

    /**
     * Whether access-token audience validation is enabled.
     * <p>
     * Defaults to {@code true}. For JWT access-token validation, disabling this option relaxes RFC 9068 validation and
     * should be used only for testing, local development, or legacy non-RFC9068 access tokens. For introspection,
     * disabling this option can be useful when the Authorization Server omits {@code aud} from introspection responses.
     *
     * @return whether access-token audience validation is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean audienceValidationEnabled();

    /**
     * RFC 7662 Token Introspection request configuration.
     * <p>
     * Used only when {@link #method()} is {@link OidcTokenValidationMethod#INTROSPECTION}. Authentication defaults to
     * {@link OidcClientAuthenticationMethod#CLIENT_SECRET_BASIC} when a client secret is available either here or at
     * the tenant level.
     *
     * @return Token Introspection request configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcIntrospectionConfig introspection();

    /**
     * RFC 8705 certificate-bound access-token validation configuration.
     * <p>
     * Applies to Protected Resource Bearer Token requests. Refreshed Authorization Code Flow access-token validation
     * continues to reject sender-constrained access tokens because the inbound request client certificate is not the
     * OAuth client certificate used at the Token Endpoint.
     *
     * @return certificate-bound access-token validation configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcCertificateBoundAccessTokenConfig certificateBoundAccessTokens();

    /**
     * Allowed JWS algorithms for JWT access tokens.
     *
     * @return allowed algorithms
     */
    @Option.Configured
    @Option.Default({"RS256"})
    @Option.Singular("allowedAlgorithm")
    List<String> allowedAlgorithms();

    /**
     * Token time validation clock skew.
     *
     * @return clock skew
     */
    @Option.Configured
    @Option.Default("PT1M")
    Duration clockSkew();
}
