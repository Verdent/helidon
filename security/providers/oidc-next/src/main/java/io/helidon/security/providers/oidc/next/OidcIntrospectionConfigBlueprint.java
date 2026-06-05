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

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * RFC 7662 Token Introspection request configuration.
 * <p>
 * The introspection endpoint authenticates the protected resource, not necessarily the OAuth client role used at the
 * Token Endpoint. RFC 7662 allows reusing Token Endpoint client authentication mechanisms, but also allows the
 * Authorization Server to require separate credentials for introspection.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7662.html">
 * RFC 7662, OAuth 2.0 Token Introspection</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8414.html#section-2">
 * RFC 8414, 2 Authorization Server Metadata</a>
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcIntrospectionConfigBlueprint {
    /**
     * Introspection Endpoint authentication method.
     * <p>
     * When omitted, the provider uses {@link OidcClientAuthenticationMethod#CLIENT_SECRET_BASIC} if either this
     * configuration or the tenant has a {@code client-secret}; otherwise it resolves to
     * {@link OidcClientAuthenticationMethod#NONE}. Introspection rejects {@code NONE}, because RFC 7662 requires
     * protected resources to authenticate to the introspection endpoint.
     *
     * @return Introspection Endpoint authentication method
     */
    @Option.Configured("auth-method")
    Optional<OidcClientAuthenticationMethod> authenticationMethod();

    /**
     * Client identifier used to authenticate this protected resource to the Introspection Endpoint.
     * <p>
     * When omitted, the tenant {@code client-id} is used.
     *
     * @return Introspection Endpoint client id
     */
    @Option.Configured
    Optional<String> clientId();

    /**
     * Client secret used to authenticate this protected resource to the Introspection Endpoint.
     * <p>
     * When omitted, the tenant {@code client-secret} is used.
     *
     * @return Introspection Endpoint client secret
     */
    @Option.Configured
    @Option.Confidential
    Optional<String> clientSecret();

    /**
     * Client assertion signing configuration used by {@link OidcClientAuthenticationMethod#CLIENT_SECRET_JWT} and
     * {@link OidcClientAuthenticationMethod#PRIVATE_KEY_JWT} at the Introspection Endpoint.
     * <p>
     * When omitted, the tenant {@code client-assertion} is used.
     *
     * @return Introspection Endpoint client assertion configuration
     */
    @Option.Configured
    Optional<OidcClientAssertionConfig> clientAssertion();
}
