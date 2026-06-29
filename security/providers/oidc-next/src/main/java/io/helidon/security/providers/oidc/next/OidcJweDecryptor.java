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
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;

final class OidcJweDecryptor {
    private final Optional<JwkKeys> decryptionKeys;
    private final String tokenDescription;

    private OidcJweDecryptor(Optional<JwkKeys> decryptionKeys, String tokenDescription) {
        this.decryptionKeys = decryptionKeys;
        this.tokenDescription = tokenDescription;
    }

    static OidcJweDecryptor create(Optional<Resource> decryptionJwk,
                                   String configKey,
                                   String tokenDescription) {
        return new OidcJweDecryptor(decryptionJwk.map(resource -> loadKeys(resource, configKey)), tokenDescription);
    }

    byte[] decrypt(String token, JwtHeaders headers) {
        JwkKeys keys = decryptionKeys.orElseThrow(() -> new IllegalStateException(
                tokenDescription + " decryption keys are not configured"));
        Jwk selectedKey = selectDecryptionKey(headers, keys);
        validateDecryptionKeyUse(selectedKey);
        return EncryptedJwt.parseToken(headers, token).decryptPayload(keys, selectedKey);
    }

    private Jwk selectDecryptionKey(JwtHeaders headers, JwkKeys keys) {
        List<Jwk> jwks = keys.keys();
        Optional<String> keyId = headers.keyId();
        if (keyId.isPresent()) {
            String id = keyId.orElseThrow();
            return keys.forKeyId(id)
                    .orElseThrow(() -> new IllegalStateException(
                            tokenDescription + " decryption key is not configured for kid: " + id));
        }
        /*
         * Spec: OpenID Connect Core 1.0, 10.2 Signing and Encryption Order
         * https://openid.net/specs/openid-connect-core-1_0.html#SigningOrder
         * Quote: "If there are multiple keys in the referenced JWK Set document, a `kid` value MUST be provided in
         * the JOSE Header."
         */
        if (jwks.size() > 1) {
            throw new IllegalStateException(
                    "Encrypted " + tokenDescription + " JWE kid is required when multiple decryption keys exist");
        }
        return jwks.getFirst();
    }

    private void validateDecryptionKeyUse(Jwk key) {
        /*
         * Spec: OpenID Connect Core 1.0, 10.2 Signing and Encryption Order
         * https://openid.net/specs/openid-connect-core-1_0.html#SigningOrder
         * Quote: "The key usage of the respective keys MUST include encryption."
         */
        key.usage()
                .filter(usage -> !Jwk.USE_ENCRYPTION.equals(usage))
                .ifPresent(usage -> {
                    throw new IllegalStateException(tokenDescription + " decryption JWK use must be enc");
                });
        key.operations()
                .filter(operations -> !operations.contains(Jwk.OPERATION_UNWRAP_KEY)
                        && !operations.contains(Jwk.OPERATION_DECRYPT))
                .ifPresent(operations -> {
                    throw new IllegalStateException(
                            tokenDescription + " decryption JWK key_ops must allow unwrapKey or decrypt");
                });
        if (!(key instanceof JwkRSA)) {
            throw new IllegalStateException(tokenDescription + " decryption JWK must be an RSA key");
        }
    }

    private static JwkKeys loadKeys(Resource resource, String configKey) {
        resource.cacheBytes();
        JwkKeys keys = JwkKeys.builder()
                .resource(resource)
                .build();
        if (keys.keys().isEmpty()) {
            throw new IllegalArgumentException(configKey + " must contain at least one JWK");
        }
        return keys;
    }
}
