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
import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.common.configurable.ResourceConfig;

/**
 * ID Token validation and decryption configuration.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">
 * OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation</a>
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">
 * OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata</a>
 */
@Prototype.Blueprint(decorator = OidcIdTokenConfigDecorator.class)
@Prototype.Configured
interface OidcIdTokenConfigBlueprint {
    /**
     * Allowed JWS algorithms for signed ID Tokens.
     * <p>
     * Defaults to {@code RS256}, the OpenID Connect Core default ID Token signing algorithm. A selected RSA verification
     * key must have a modulus of at least 2048 bits. A JWK without the optional {@code alg} member may be used with any
     * compatible allowed algorithm; a declared JWK {@code alg} must match the ID Token header.
     * When the ID Token omits {@code kid}, the referenced JWK Set must contain exactly one key and that key must satisfy
     * all verification constraints.
     *
     * @return allowed ID Token JWS algorithms
     */
    @Option.Configured
    @Option.Default({"RS256"})
    @Option.Singular("allowedAlgorithm")
    List<String> allowedAlgorithms();

    /**
     * Allowed JWE {@code alg} algorithms for encrypted ID Tokens.
     * <p>
     * Defaults to {@code RSA-OAEP-256} and {@code RSA-OAEP}, the supported key management algorithms.
     * Values are case-sensitive. Unsupported values, including {@code RSA1_5}, are rejected when an enabled tenant
     * is built. RFC 8725 section 3.2 recommends avoiding RSA-PKCS1 v1.5 encryption in favor of RSAES-OAEP.
     *
     * @return allowed ID Token JWE key management algorithms
     * @see io.helidon.security.jwt.EncryptedJwt.SupportedAlgorithm#supported()
     */
    @Option.Configured
    @Option.Default({"RSA-OAEP-256", "RSA-OAEP"})
    @Option.Singular("allowedEncryptionAlgorithm")
    List<String> allowedEncryptionAlgorithms();

    /**
     * Allowed JWE {@code enc} algorithms for encrypted ID Tokens.
     * <p>
     * Defaults to {@code A256GCM} and {@code A128CBC-HS256}. The latter is the OpenID Connect Dynamic Client
     * Registration default content encryption algorithm when ID Token encryption is registered and {@code enc} is omitted.
     * Supported values are {@code A128GCM}, {@code A192GCM}, {@code A256GCM}, {@code A128CBC-HS256},
     * {@code A192CBC-HS384}, and {@code A256CBC-HS512}. Values are case-sensitive; unsupported values are rejected
     * when an enabled tenant is built.
     *
     * @return allowed ID Token JWE content encryption algorithms
     * @see io.helidon.security.jwt.EncryptedJwt.SupportedEncryption
     */
    @Option.Configured
    @Option.Default({"A256GCM", "A128CBC-HS256"})
    @Option.Singular("allowedContentEncryptionAlgorithm")
    List<String> allowedContentEncryptionAlgorithms();

    /**
     * Additional ID Token audience values trusted by this client.
     * <p>
     * The configured {@code client-id} is always required as an ID Token audience and should not be listed here. This
     * option is only for other {@code aud} values that may appear in the same ID Token.
     *
     * @return trusted additional ID Token audiences
     */
    @Option.Configured
    @Option.Singular("trustedAdditionalAudience")
    List<String> trustedAdditionalAudiences();

    /**
     * ID Token time validation clock skew.
     *
     * @return ID Token clock skew
     */
    @Option.Configured
    @Option.Default("PT1M")
    Duration clockSkew();

    /**
     * Private JWK Set resource configuration used to decrypt encrypted ID Tokens.
     * <p>
     * This is local RP/client key material. It is not the OpenID Provider {@code jwks_uri}, which contains public
     * verification keys used after the encrypted ID Token is decrypted. RSA keys must have a modulus of at least
     * 2048 bits. A declared JWK {@code alg} must match the JWE header; an omitted JWK {@code alg} remains unconstrained.
     * Required when {@link #encryptionRequired()} is {@code true} for an enabled tenant; otherwise optional.
     * Filesystem paths, classpath resources, and supplied plaintext or Base64 content are supported. URI sources are
     * rejected before opening, including when this configuration is built independently of a tenant.
     * Each decryptor loads its own resource and retains its parsed keys; local sources must remain available when new
     * consumers are created. Supplied content can come from an explicitly managed secure external secret store.
     *
     * @return ID Token decryption JWK Set resource configuration
     */
    @Option.Configured("decryption-jwk")
    @Option.Confidential
    Optional<ResourceConfig> decryptionJwk();

    /**
     * Whether ID Tokens must be encrypted.
     * <p>
     * Defaults to {@code false}. When enabled, a signed-only ID Token is rejected. An enabled tenant must also
     * configure {@link #decryptionJwk()}; otherwise tenant configuration fails before initialization.
     *
     * @return whether ID Token encryption is required
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean encryptionRequired();
}
