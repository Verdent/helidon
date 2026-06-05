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
