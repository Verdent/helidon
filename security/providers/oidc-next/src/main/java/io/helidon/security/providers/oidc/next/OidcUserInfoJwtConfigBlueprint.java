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
 * UserInfo JWT response configuration matching the values negotiated during client registration.
 *
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata">
 * OpenID Connect Dynamic Client Registration 1.0, 2 Client Metadata</a>
 */
@Prototype.Blueprint(decorator = OidcUserInfoJwtConfigDecorator.class)
@Prototype.Configured
interface OidcUserInfoJwtConfigBlueprint {
    /**
     * Exact JWS {@code alg} registered as {@code userinfo_signed_response_alg}.
     * <p>
     * When configured without {@link #encryptionAlgorithm()}, the UserInfo response must be a signed JWT. When both
     * algorithms are configured, the response must be signed and then encrypted as a Nested JWT. A selected RSA
     * verification key must have a modulus of at least 2048 bits. A JWK without the optional {@code alg} member may be
     * used with this compatible registered algorithm; a declared JWK {@code alg} must match it.
     * When the JWT omits {@code kid}, the referenced JWK Set must contain exactly one key and that key must satisfy all
     * verification constraints.
     *
     * @return registered UserInfo signing algorithm
     */
    @Option.Configured
    Optional<String> signingAlgorithm();

    /**
     * Exact JWE {@code alg} registered as {@code userinfo_encrypted_response_alg}.
     * <p>
     * Supported values are {@code RSA-OAEP-256} and {@code RSA-OAEP}. Values are case-sensitive. Unsupported values,
     * including {@code RSA1_5}, are rejected when UserInfo is enabled for an enabled tenant.
     *
     * @return registered UserInfo JWE key management algorithm
     * @see io.helidon.security.jwt.EncryptedJwt.SupportedAlgorithm#supported()
     */
    @Option.Configured
    Optional<String> encryptionAlgorithm();

    /**
     * Exact JWE {@code enc} registered as {@code userinfo_encrypted_response_enc}.
     * <p>
     * OpenID Connect registration defines {@code A128CBC-HS256} as the default when
     * {@link #encryptionAlgorithm()} is configured and this option is omitted.
     * Supported values are {@code A128GCM}, {@code A192GCM}, {@code A256GCM}, {@code A128CBC-HS256},
     * {@code A192CBC-HS384}, and {@code A256CBC-HS512}. Values are case-sensitive; unsupported values are rejected
     * when UserInfo is enabled for an enabled tenant.
     *
     * @return registered UserInfo JWE content encryption algorithm
     * @see io.helidon.security.jwt.EncryptedJwt.SupportedEncryption
     */
    @Option.Configured
    Optional<String> contentEncryptionAlgorithm();

    /**
     * Private RP JWK Set resource configuration used to decrypt encrypted UserInfo responses.
     * <p>
     * RSA keys must have a modulus of at least 2048 bits. A declared JWK {@code alg} must match the registered JWE
     * algorithm; an omitted JWK {@code alg} remains unconstrained.
     * Filesystem paths, classpath resources, and supplied plaintext or Base64 content are supported. URI sources are
     * rejected before opening, including when this configuration is built independently of a tenant.
     * Each decryptor loads its own resource and retains its parsed keys; local sources must remain available when new
     * consumers are created. Supplied content can come from an explicitly managed secure external secret store.
     *
     * @return UserInfo decryption JWK Set resource configuration
     */
    @Option.Configured("decryption-jwk")
    @Option.Confidential
    Optional<ResourceConfig> decryptionJwk();

    /**
     * Clock skew used when validating optional time claims in signed UserInfo JWTs.
     *
     * @return UserInfo JWT clock skew
     */
    @Option.Configured
    @Option.Default("PT1M")
    Duration clockSkew();
}
