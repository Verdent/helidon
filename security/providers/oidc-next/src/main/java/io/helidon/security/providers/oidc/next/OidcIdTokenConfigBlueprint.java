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
import io.helidon.common.configurable.Resource;

/**
 * ID Token validation and decryption configuration.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">
 * OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation</a>
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">
 * OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata</a>
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcIdTokenConfigBlueprint {
    /**
     * Allowed JWS algorithms for signed ID Tokens.
     * <p>
     * Defaults to {@code RS256}, the OpenID Connect Core default ID Token signing algorithm.
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
     * Defaults to {@code RSA-OAEP-256} and {@code RSA-OAEP}. {@code RSA1_5} is not enabled by default because
     * RFC 7516 describes downgrade and oracle risks for that algorithm.
     *
     * @return allowed ID Token JWE key management algorithms
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
     *
     * @return allowed ID Token JWE content encryption algorithms
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
     * Private JWK Set resource used to decrypt encrypted ID Tokens.
     * <p>
     * This is local RP/client key material. It is not the OpenID Provider {@code jwks_uri}, which contains public
     * verification keys used after the encrypted ID Token is decrypted.
     *
     * @return ID Token decryption JWK Set resource
     */
    @Option.Configured("decryption-jwk")
    @Option.Confidential
    Optional<Resource> decryptionJwk();

    /**
     * Whether ID Tokens must be encrypted.
     * <p>
     * Defaults to {@code false}. When enabled, a signed-only ID Token is rejected.
     *
     * @return whether ID Token encryption is required
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean encryptionRequired();
}
