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
import io.helidon.common.configurable.Resource;

/**
 * UserInfo JWT response configuration matching the values negotiated during client registration.
 *
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata">
 * OpenID Connect Dynamic Client Registration 1.0, 2 Client Metadata</a>
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcUserInfoJwtConfigBlueprint {
    /**
     * Default JWE content encryption algorithm defined by OpenID Connect client registration.
     */
    String DEFAULT_CONTENT_ENCRYPTION_ALGORITHM = "A128CBC-HS256";

    /**
     * Exact JWS {@code alg} registered as {@code userinfo_signed_response_alg}.
     * <p>
     * When configured without {@link #encryptionAlgorithm()}, the UserInfo response must be a signed JWT. When both
     * algorithms are configured, the response must be signed and then encrypted as a Nested JWT.
     *
     * @return registered UserInfo signing algorithm
     */
    @Option.Configured
    Optional<String> signingAlgorithm();

    /**
     * Exact JWE {@code alg} registered as {@code userinfo_encrypted_response_alg}.
     *
     * @return registered UserInfo JWE key management algorithm
     */
    @Option.Configured
    Optional<String> encryptionAlgorithm();

    /**
     * Exact JWE {@code enc} registered as {@code userinfo_encrypted_response_enc}.
     * <p>
     * OpenID Connect registration defines {@value #DEFAULT_CONTENT_ENCRYPTION_ALGORITHM} as the default when
     * {@link #encryptionAlgorithm()} is configured and this option is omitted.
     *
     * @return registered UserInfo JWE content encryption algorithm
     */
    @Option.Configured
    Optional<String> contentEncryptionAlgorithm();

    /**
     * Private RP JWK Set resource used to decrypt encrypted UserInfo responses.
     *
     * @return UserInfo decryption JWK Set resource
     */
    @Option.Configured("decryption-jwk")
    @Option.Confidential
    Optional<Resource> decryptionJwk();

    /**
     * Clock skew used when validating optional time claims in signed UserInfo JWTs.
     *
     * @return UserInfo JWT clock skew
     */
    @Option.Configured
    @Option.Default("PT1M")
    Duration clockSkew();
}
