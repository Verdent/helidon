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

import java.util.List;
import java.util.Optional;

import io.helidon.common.configurable.Resource;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.JwtHeaders;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;

final class OidcIdTokenDecryptor {
    private final Optional<JwkKeys> decryptionKeys;
    private final boolean encryptionRequired;
    private final List<String> allowedEncryptionAlgorithms;
    private final List<String> allowedContentEncryptionAlgorithms;

    private OidcIdTokenDecryptor(Optional<JwkKeys> decryptionKeys,
                                 boolean encryptionRequired,
                                 List<String> allowedEncryptionAlgorithms,
                                 List<String> allowedContentEncryptionAlgorithms) {
        this.decryptionKeys = decryptionKeys;
        this.encryptionRequired = encryptionRequired;
        this.allowedEncryptionAlgorithms = List.copyOf(allowedEncryptionAlgorithms);
        this.allowedContentEncryptionAlgorithms = List.copyOf(allowedContentEncryptionAlgorithms);
    }

    static OidcIdTokenDecryptor create(OidcTenantConfig tenantConfig) {
        OidcIdTokenConfig idToken = tenantConfig.idToken();
        return new OidcIdTokenDecryptor(idToken.decryptionJwk()
                                                  .map(OidcIdTokenDecryptor::loadKeys),
                                          idToken.encryptionRequired(),
                                          idToken.allowedEncryptionAlgorithms(),
                                          idToken.allowedContentEncryptionAlgorithms());
    }

    OidcResolvedIdToken resolve(String token) {
        JwtHeaders headers = JwtHeaders.parseToken(token);
        if (headers.encryption().isEmpty()) {
            if (encryptionRequired) {
                /*
                 * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
                 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                 * Quote: "If encryption was negotiated with the OP at Registration time and the ID Token is not
                 * encrypted, the RP SHOULD reject it".
                 */
                throw new IllegalStateException("ID Token encryption is required");
            }
            return new OidcResolvedIdToken(token, false, SignedJwt.parseToken(headers, token));
        }

        validateEncryptedHeaders(headers);
        JwkKeys keys = decryptionKeys.orElseThrow(() -> new IllegalStateException(
                "ID Token decryption keys are not configured"));
        Jwk selectedKey = selectDecryptionKey(headers, keys);
        validateDecryptionKeyUse(selectedKey);
        EncryptedJwt encryptedJwt = EncryptedJwt.parseToken(headers, token);
        return new OidcResolvedIdToken(token, true, encryptedJwt.decrypt(keys, selectedKey));
    }

    private void validateEncryptedHeaders(JwtHeaders headers) {
        /*
         * Spec: RFC 7519, 5.2 cty Header Parameter
         * https://www.rfc-editor.org/rfc/rfc7519.html#section-5.2
         * Quote: "In the case that nested signing or encryption is employed, this Header Parameter MUST be present".
         */
        if (headers.contentType().filter("JWT"::equalsIgnoreCase).isEmpty()) {
            throw new IllegalStateException("Encrypted ID Token must be a Nested JWT with cty=JWT");
        }
        String algorithm = headers.algorithm()
                .orElseThrow(() -> new IllegalStateException("Encrypted ID Token JWE alg header is missing"));
        if (!allowedEncryptionAlgorithms.contains(algorithm)) {
            throw new IllegalStateException("Encrypted ID Token JWE alg header is not allowed: " + algorithm);
        }
        String contentEncryption = headers.encryption()
                .orElseThrow(() -> new IllegalStateException("Encrypted ID Token JWE enc header is missing"));
        if (!allowedContentEncryptionAlgorithms.contains(contentEncryption)) {
            throw new IllegalStateException("Encrypted ID Token JWE enc header is not allowed: " + contentEncryption);
        }
    }

    private static Jwk selectDecryptionKey(JwtHeaders headers, JwkKeys keys) {
        List<Jwk> jwks = keys.keys();
        Optional<String> keyId = headers.keyId();
        if (keyId.isPresent()) {
            String id = keyId.orElseThrow();
            return keys.forKeyId(id)
                    .orElseThrow(() -> new IllegalStateException(
                            "ID Token decryption key is not configured for kid: " + id));
        }
        /*
         * Spec: OpenID Connect Core 1.0, 10.2 Signing and Encryption Order
         * https://openid.net/specs/openid-connect-core-1_0.html#SigningOrder
         * Quote: "If there are multiple keys in the referenced JWK Set document, a `kid` value MUST be provided in
         * the JOSE Header."
         */
        if (jwks.size() > 1) {
            throw new IllegalStateException("Encrypted ID Token JWE kid is required when multiple decryption keys exist");
        }
        return jwks.getFirst();
    }

    private static void validateDecryptionKeyUse(Jwk key) {
        /*
         * Spec: OpenID Connect Core 1.0, 10.2 Signing and Encryption Order
         * https://openid.net/specs/openid-connect-core-1_0.html#SigningOrder
         * Quote: "The key usage of the respective keys MUST include encryption."
         */
        key.usage()
                .filter(usage -> !Jwk.USE_ENCRYPTION.equals(usage))
                .ifPresent(usage -> {
                    throw new IllegalStateException("ID Token decryption JWK use must be enc");
                });
        key.operations()
                .filter(operations -> !operations.contains(Jwk.OPERATION_UNWRAP_KEY)
                        && !operations.contains(Jwk.OPERATION_DECRYPT))
                .ifPresent(operations -> {
                    throw new IllegalStateException("ID Token decryption JWK key_ops must allow unwrapKey or decrypt");
                });
    }

    private static JwkKeys loadKeys(Resource resource) {
        resource.cacheBytes();
        JwkKeys keys = JwkKeys.builder()
                .resource(resource)
                .build();
        List<Jwk> jwks = keys.keys();
        if (jwks.isEmpty()) {
            throw new IllegalArgumentException("id-token.decryption-jwk must contain at least one JWK");
        }
        return keys;
    }

    record OidcResolvedIdToken(String rawToken, boolean encrypted, SignedJwt signedJwt) {
    }
}
