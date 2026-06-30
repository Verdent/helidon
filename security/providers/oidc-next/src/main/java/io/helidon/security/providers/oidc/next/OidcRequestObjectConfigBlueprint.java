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
import io.helidon.common.configurable.ResourceConfig;

/**
 * Secured Request Object configuration for Authorization Code Flow Authentication Requests.
 * <p>
 * RFC 9101 signs, or signs and encrypts, Authorization Request parameters into a JWT and sends that JWT as the
 * {@code request} parameter. The configured private signing JWK material must belong to this OAuth client registration
 * and must be registered at the Authorization Server for Request Object signature validation. Encryption uses a public
 * key from the Authorization Server JWK Set.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9101.html">
 * OAuth 2.0 JWT-Secured Authorization Request (JAR)</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#RequestObject">
 * OpenID Connect Core 1.0, 6.1 Passing a Request Object by Value</a>
 */
@Prototype.Blueprint
@Prototype.Configured
@Prototype.CustomMethods(OidcRequestObjectConfigSupport.class)
interface OidcRequestObjectConfigBlueprint {
    String DEFAULT_CONTENT_ENCRYPTION_ALGORITHM = "A128CBC-HS256";

    /**
     * Request Object mode.
     *
     * @return Request Object mode
     */
    @Option.Configured
    @Option.Default("AUTO")
    OidcRequestObjectMode mode();

    /**
     * JWS {@code alg} header value used to sign the Request Object JWT.
     * <p>
     * When omitted, the selected JWK algorithm is used. When configured, this value must match the selected JWK
     * algorithm.
     *
     * @return Request Object JWS algorithm
     */
    @Option.Configured
    Optional<String> signingAlgorithm();

    /**
     * JWS {@code kid} header value used for the Request Object.
     * <p>
     * This selects the JWK used for signing. If omitted, the configured JWK resource must contain exactly one key.
     *
     * @return Request Object JWK key id
     */
    @Option.Configured
    Optional<String> signingKeyId();

    /**
     * Private JWK Set resource configuration used to sign Request Objects.
     * <p>
     * This is local client key material. It is not the OpenID Provider {@code jwks_uri}, which contains public
     * verification keys. URI-backed resources are rejected before the resource is created; use classpath, file, or
     * configured content resources.
     *
     * @return private JWK Set resource configuration
     */
    @Option.Configured
    @Option.Confidential
    Optional<ResourceConfig> signingJwk();

    /**
     * JWE {@code alg} header value used to encrypt the signed Request Object.
     * <p>
     * When configured, the signed Request Object is encrypted as a Nested JWT using an Authorization Server public key
     * obtained from its {@code jwks_uri}. Supported values are {@code RSA-OAEP-256} and {@code RSA-OAEP}.
     *
     * @return Request Object JWE key management algorithm
     */
    @Option.Configured
    Optional<String> encryptionAlgorithm();

    /**
     * JWE {@code enc} header value used to encrypt the signed Request Object.
     * <p>
     * OpenID Connect registration defines {@value #DEFAULT_CONTENT_ENCRYPTION_ALGORITHM} as the default when
     * {@link #encryptionAlgorithm()} is configured and this option is omitted.
     *
     * @return Request Object JWE content encryption algorithm
     */
    @Option.Configured
    Optional<String> contentEncryptionAlgorithm();

    /**
     * Key id of the Authorization Server public JWK used to encrypt the signed Request Object.
     * <p>
     * When omitted, the first eligible key in the Authorization Server JWK Set is selected. When configured, the value
     * selects an exact key and allows the JWK Set manager to refresh when that key is not currently cached.
     *
     * @return Authorization Server encryption JWK key id
     */
    @Option.Configured
    Optional<String> encryptionKeyId();

    /**
     * Request Object lifetime used to calculate the JWT {@code exp} claim from the current time.
     *
     * @return Request Object lifetime
     */
    @Option.Configured
    @Option.Default("PT1M")
    Duration lifetime();
}
