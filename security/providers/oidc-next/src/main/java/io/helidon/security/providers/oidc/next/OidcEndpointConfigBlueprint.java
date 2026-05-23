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

/**
 * OpenID Provider endpoint and well-known metadata configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcEndpointConfigBlueprint {
    /**
     * Well-known URI used to retrieve well-known metadata.
     *
     * @return well-known URI
     */
    @Option.Configured
    Optional<URI> wellKnownUri();

    /**
     * Authorization Endpoint URI.
     *
     * @return Authorization Endpoint URI
     */
    @Option.Configured
    Optional<URI> authorizationEndpointUri();

    /**
     * Token Endpoint URI.
     *
     * @return Token Endpoint URI
     */
    @Option.Configured
    Optional<URI> tokenEndpointUri();

    /**
     * JSON Web Key Set URI.
     *
     * @return JWKS URI
     */
    @Option.Configured
    Optional<URI> jwksUri();

    /**
     * Token Introspection Endpoint URI.
     *
     * @return introspection endpoint URI
     */
    @Option.Configured
    Optional<URI> introspectionEndpointUri();

    /**
     * Whether OpenID Connect endpoint URIs, OIDC post-logout redirect URIs, and OIDC outbound bearer-token targets must
     * use transport-layer security.
     * <p>
     * WARNING: Disabling this option permits using non-TLS endpoint URIs and post-logout redirect URIs, and permits
     * Token Propagation or Client Credentials Grant to attach Bearer tokens to non-HTTPS outbound target URIs. This can
     * expose access tokens, client credentials, and token signature verification keys, and is not compliant with OpenID
     * Connect and OAuth endpoint TLS requirements. It should only be used for isolated tests or equivalent non-production
     * environments where the endpoint and key source are controlled.
     * <p>
     * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata,
     * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">section 3</a>.
     * Quote: "This URL MUST use the `https` scheme".
     * <p>
     * Spec: RFC 7662, 2 Introspection Endpoint,
     * <a href="https://www.rfc-editor.org/rfc/rfc7662.html#section-2">section 2</a>.
     * Quote: "MUST be protected by a transport-layer security mechanism".
     *
     * @return whether OpenID Connect endpoint URIs, post-logout redirect URIs, and OIDC outbound bearer-token targets
     *         must use transport-layer security
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean tlsRequired();

    /**
     * UserInfo Endpoint URI.
     *
     * @return UserInfo Endpoint URI
     */
    @Option.Configured
    Optional<URI> userInfoEndpointUri();

    /**
     * OpenID Provider End Session Endpoint URI.
     *
     * @return End Session Endpoint URI
     */
    @Option.Configured
    Optional<URI> endSessionEndpointUri();
}
