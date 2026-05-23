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
import io.helidon.builder.api.Prototype;
import io.helidon.webclient.api.WebClientConfig;

/**
 * OpenID Connect tenant configuration.
 */
@Prototype.Blueprint(decorator = OidcConfigSupport.TenantDecorator.class)
@Prototype.Configured
interface OidcTenantConfigBlueprint {
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
     * Token Endpoint client authentication method.
     * <p>
     * When omitted, the provider uses {@link OidcClientAuthenticationMethod#CLIENT_SECRET_BASIC} if
     * {@link #clientSecret()} is configured, otherwise {@link OidcClientAuthenticationMethod#NONE}.
     *
     * @return Token Endpoint client authentication method
     */
    @Option.Configured("token-endpoint-auth-method")
    Optional<OidcClientAuthenticationMethod> tokenEndpointAuthenticationMethod();

    /**
     * WebClient configuration used for outbound requests to the OpenID Provider or Authorization Server.
     * <p>
     * This client is used for discovery, JSON Web Key Set loading, Token Endpoint requests, and introspection.
     *
     * @return WebClient configuration
     */
    @Option.Configured("webclient")
    @Option.Default("create()")
    WebClientConfig webClient();

    /**
     * OpenID Provider endpoint and discovery settings.
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

    /**
     * Outbound Token Propagation and Client Credentials Grant configuration.
     *
     * @return outbound configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcOutboundConfig outbound();
}
