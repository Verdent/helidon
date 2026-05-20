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
 * OpenID Provider endpoint and discovery configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcEndpointConfigBlueprint {
    /**
     * OpenID Provider Configuration discovery URI.
     *
     * @return discovery URI
     */
    @Option.Configured
    Optional<URI> discoveryUri();

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
     * UserInfo Endpoint URI.
     *
     * @return UserInfo Endpoint URI
     */
    @Option.Configured
    Optional<URI> userInfoEndpointUri();

    /**
     * RP-Initiated Logout endpoint URI.
     *
     * @return end session endpoint URI
     */
    @Option.Configured
    Optional<URI> endSessionEndpointUri();
}
