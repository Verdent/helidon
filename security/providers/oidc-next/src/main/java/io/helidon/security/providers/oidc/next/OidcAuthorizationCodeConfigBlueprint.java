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
import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * OpenID Connect Authorization Code Flow configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcAuthorizationCodeConfigBlueprint {
    /**
     * Whether Authorization Code Flow initiation is enabled.
     *
     * @return whether Authorization Code Flow initiation is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean enabled();

    /**
     * Redirection Endpoint URI used as the Authentication Request {@code redirect_uri}.
     *
     * @return Redirection Endpoint URI
     */
    @Option.Configured
    @Option.Default("/oidc/callback")
    Optional<URI> redirectionEndpointUri();

    /**
     * Authentication Request scopes.
     *
     * @return scopes
     */
    @Option.Configured
    @Option.Default({"openid"})
    @Option.Singular("scope")
    List<String> scopes();

    /**
     * Authentication Request prompt values.
     *
     * @return prompt values
     */
    @Option.Configured
    @Option.Singular("prompt")
    List<String> prompts();

    /**
     * Resource indicators sent as repeated {@code resource} parameters in the Authentication Request.
     *
     * @return resource indicators
     */
    @Option.Configured
    @Option.Singular("resource")
    List<String> resources();

    /**
     * Pushed Authorization Request mode.
     * <p>
     * When enabled or required, the provider sends the Authentication Request parameters directly to the Authorization
     * Server's Pushed Authorization Request endpoint, then redirects the browser with the returned {@code request_uri}.
     *
     * @return Pushed Authorization Request mode
     */
    @Option.Configured("pushed-authorization-requests")
    @Option.Default("AUTO")
    OidcPushedAuthorizationRequestMode pushedAuthorizationRequests();

    /**
     * Signed Request Object configuration.
     * <p>
     * When enabled or required, the provider signs the Authentication Request parameters as an RFC 9101 Request Object
     * and sends that JWT as the {@code request} parameter. This can be combined with Pushed Authorization Requests; in
     * that case the signed {@code request} parameter is sent to the PAR endpoint and the browser receives the returned
     * {@code request_uri}.
     *
     * @return signed Request Object configuration
     */
    @Option.Configured("request-object")
    @Option.Default("create()")
    OidcRequestObjectConfig requestObject();

    /**
     * Whether Proof Key for Code Exchange is required for Authorization Code Flow.
     * <p>
     * Defaults to {@code true}. Disable only for confidential-client compatibility with a legacy Authorization Server
     * that cannot process PKCE. Public clients, where Token Endpoint authentication is
     * {@link OidcClientAuthenticationMethod#NONE}, must use PKCE.
     *
     * @return whether PKCE is required
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean pkceRequired();

    /**
     * PKCE code challenge method.
     * <p>
     * Defaults to {@link OidcPkceMethod#S256}. Use {@link OidcPkceMethod#PLAIN} only for confidential-client
     * compatibility with a legacy Authorization Server that cannot process {@code S256}. Public clients, where Token
     * Endpoint authentication is {@link OidcClientAuthenticationMethod#NONE}, must use {@link OidcPkceMethod#S256}.
     *
     * @return PKCE method
     */
    @Option.Configured
    @Option.Default("S256")
    OidcPkceMethod pkceMethod();
}
