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

/**
 * Access-token validation method for Protected Resource authentication.
 * <p>
 * This is Helidon configuration, not a single OpenID Connect registry. Each value selects one standards-defined
 * validation strategy for bearer access tokens received by a Protected Resource.
 */
public enum OidcTokenValidationMethod {
    /**
     * Local JWT validation.
     * <p>
     * The access token is parsed as a JWT, its JWS signature is verified with JSON Web Key material from
     * {@code jwks-uri} or well-known metadata {@code jwks_uri}, and JWT claims such as issuer, expiration, and
     * audience are validated.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7519.html">RFC 7519, JSON Web Token (JWT)</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html">RFC 7517, JSON Web Key (JWK)</a>
     * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">
     * OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata</a>
     */
    JWT,

    /**
     * OAuth 2.0 Token Introspection.
     * <p>
     * The access token is sent to the configured introspection endpoint, and the response is validated according to
     * RFC 7662.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7662.html">RFC 7662, OAuth 2.0 Token Introspection</a>
     */
    INTROSPECTION
}
