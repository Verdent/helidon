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

import java.net.URI;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.webclient.api.WebClientConfig;

/**
 * OpenID Connect tenant options that can be configured either as a single tenant at provider root, or under a named
 * tenant in multi-tenant configuration.
 */
interface OidcTenantConfigOptionsBlueprint {
    /**
     * Whether this tenant is enabled.
     *
     * @return whether this tenant is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean enabled();

    /**
     * Issuer Identifier expected for this tenant.
     *
     * @return issuer identifier
     */
    @Option.Configured
    Optional<URI> issuer();

    /**
     * OAuth 2.0 client identifier.
     *
     * @return client id
     */
    @Option.Configured
    Optional<String> clientId();

    /**
     * OAuth 2.0 client secret.
     *
     * @return client secret
     */
    @Option.Configured
    @Option.Confidential
    Optional<String> clientSecret();

    /**
     * Token Endpoint client authentication method; mutual TLS methods require enabled tenant {@code webclient.tls} with
     * private key plus certificate chain, an SSL context, or a custom TLS manager.
     * <p>
     * When omitted, the provider uses {@link OidcClientAuthenticationMethod#CLIENT_SECRET_BASIC} if
     * {@link #clientSecret()} is configured, otherwise {@link OidcClientAuthenticationMethod#NONE}.
     * {@link OidcClientAuthenticationMethod#TLS_CLIENT_AUTH} and
     * {@link OidcClientAuthenticationMethod#SELF_SIGNED_TLS_CLIENT_AUTH} require enabled tenant
     * {@code webclient.tls} with private key plus certificate chain, an SSL context, or a custom TLS manager.
     *
     * @return Token Endpoint client authentication method
     */
    @Option.Configured("token-endpoint-auth-method")
    Optional<OidcClientAuthenticationMethod> tokenEndpointAuthenticationMethod();

    /**
     * Token Endpoint client assertion configuration used by
     * {@link OidcClientAuthenticationMethod#CLIENT_SECRET_JWT} and
     * {@link OidcClientAuthenticationMethod#PRIVATE_KEY_JWT}.
     *
     * @return Token Endpoint client assertion configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcClientAssertionConfig clientAssertion();

    /**
     * WebClient configuration used for outbound requests to the OpenID Provider or Authorization Server; for RFC 8705
     * mutual TLS, TLS must be enabled and provide private key plus certificate chain, an SSL context, or a custom TLS
     * manager.
     * <p>
     * This client is used for well-known metadata requests, JSON Web Key Set loading, Token Endpoint
     * requests, introspection, and UserInfo requests. When using
     * {@link OidcClientAuthenticationMethod#TLS_CLIENT_AUTH} or
     * {@link OidcClientAuthenticationMethod#SELF_SIGNED_TLS_CLIENT_AUTH}, tenant {@code webclient.tls} must be
     * enabled and provide private key plus certificate chain, an SSL context, or a custom TLS manager.
     *
     * @return WebClient configuration
     */
    @Option.Configured("webclient")
    @Option.Default("create()")
    WebClientConfig webClient();

    /**
     * JSON Web Key Set reload policy.
     *
     * @return JWK Set reload policy
     */
    @Option.Configured
    @Option.Default("create()")
    OidcJwkSetConfig jwkSet();

    /**
     * OpenID Provider endpoint and well-known metadata settings.
     *
     * @return endpoint configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcEndpointConfig endpoints();

    /**
     * Protected Resource / Resource Server configuration.
     *
     * @return protected resource configuration
     */
    @Option.Configured
    Optional<OidcProtectedResourceConfig> protectedResource();

    /**
     * Authorization Code Flow configuration.
     *
     * @return Authorization Code Flow configuration
     */
    @Option.Configured
    Optional<OidcAuthorizationCodeConfig> authorizationCode();

    /**
     * Endpoint authentication policy.
     * <p>
     * If {@link OidcEndpointPolicyConfig#acceptedCredentials()} is omitted, accepted credentials are inferred from the
     * enabled tenant features: Protected Resource accepts Bearer tokens, and Authorization Code Flow accepts the local
     * authentication cookie.
     *
     * @return endpoint authentication policy
     */
    @Option.Configured
    @Option.Default("create()")
    OidcEndpointPolicyConfig endpointPolicy();

    /**
     * Local OpenID Connect logout endpoint configuration.
     *
     * @return logout configuration
     */
    @Option.Configured
    Optional<OidcLogoutConfig> logout();

    /**
     * UserInfo request configuration for Authorization Code Flow local authentication.
     *
     * @return UserInfo request configuration
     */
    @Option.Configured
    Optional<OidcUserInfoConfig> userInfo();

    /**
     * Token transport configuration.
     *
     * @return token transport configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcTokenTransportConfig tokenTransport();

    /**
     * Subject mapping configuration.
     *
     * @return subject mapping configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcSubjectMappingConfig subjectMapping();

    /**
     * Cookie configuration used by OIDC stateful flows.
     *
     * @return cookie configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcCookieConfig cookies();
}
