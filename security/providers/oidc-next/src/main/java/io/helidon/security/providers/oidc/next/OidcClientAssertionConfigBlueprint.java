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
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.common.configurable.Resource;

/**
 * Client assertion configuration.
 * <p>
 * Used by {@link OidcClientAuthenticationMethod#CLIENT_SECRET_JWT} and
 * {@link OidcClientAuthenticationMethod#PRIVATE_KEY_JWT} when authenticating to Authorization Server endpoints such as
 * the Token Endpoint or Introspection Endpoint. OpenID Connect Core 1.0, section {@code 9 Client Authentication},
 * requires these methods to send {@code client_assertion_type} and {@code client_assertion}; the assertion JWT uses
 * {@code iss}, {@code sub}, {@code aud}, {@code jti}, and {@code exp} claims.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">
 * OpenID Connect Core 1.0, 9 Client Authentication</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7523.html">
 * RFC 7523, OAuth JWT Assertion Profiles</a>
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcClientAssertionConfigBlueprint {
    /**
     * JWS {@code alg} header value used to sign the client assertion JWT.
     * <p>
     * When omitted, {@link OidcClientAuthenticationMethod#CLIENT_SECRET_JWT} uses {@code HS256}, and
     * {@link OidcClientAuthenticationMethod#PRIVATE_KEY_JWT} uses the algorithm configured on the selected JWK.
     * When configured for {@code PRIVATE_KEY_JWT}, this value must match the selected JWK algorithm.
     *
     * @return client assertion JWS algorithm
     */
    @Option.Configured
    Optional<String> algorithm();

    /**
     * JWS {@code kid} header value used for the client assertion.
     * <p>
     * For {@link OidcClientAuthenticationMethod#PRIVATE_KEY_JWT}, this selects the JWK used for signing. If omitted,
     * the configured JWK resource must contain exactly one key. For
     * {@link OidcClientAuthenticationMethod#CLIENT_SECRET_JWT}, this is written to the assertion JWT header when
     * configured.
     *
     * @return client assertion JWK key id
     */
    @Option.Configured
    Optional<String> keyId();

    /**
     * Private JWK Set resource used to sign a {@link OidcClientAuthenticationMethod#PRIVATE_KEY_JWT} client assertion.
     * <p>
     * This is local client key material. It is not the OpenID Provider {@code jwks_uri}, which contains public
     * verification keys.
     *
     * @return private JWK Set resource
     */
    @Option.Configured
    @Option.Confidential
    Optional<Resource> jwk();

    /**
     * Client assertion lifetime used to calculate the JWT {@code exp} claim from the current time.
     *
     * @return client assertion lifetime
     */
    @Option.Configured
    @Option.Default("PT1M")
    Duration lifetime();
}
