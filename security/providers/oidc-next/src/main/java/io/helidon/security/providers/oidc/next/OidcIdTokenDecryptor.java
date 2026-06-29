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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import io.helidon.security.jwt.JwtHeaders;
import io.helidon.security.jwt.SignedJwt;

final class OidcIdTokenDecryptor {
    private final OidcJweDecryptor jweDecryptor;
    private final boolean encryptionRequired;
    private final List<String> allowedEncryptionAlgorithms;
    private final List<String> allowedContentEncryptionAlgorithms;

    private OidcIdTokenDecryptor(OidcJweDecryptor jweDecryptor,
                                 boolean encryptionRequired,
                                 List<String> allowedEncryptionAlgorithms,
                                 List<String> allowedContentEncryptionAlgorithms) {
        this.jweDecryptor = jweDecryptor;
        this.encryptionRequired = encryptionRequired;
        this.allowedEncryptionAlgorithms = List.copyOf(allowedEncryptionAlgorithms);
        this.allowedContentEncryptionAlgorithms = List.copyOf(allowedContentEncryptionAlgorithms);
    }

    static OidcIdTokenDecryptor create(OidcTenantConfig tenantConfig) {
        OidcIdTokenConfig idToken = tenantConfig.idToken();
        return new OidcIdTokenDecryptor(OidcJweDecryptor.create(idToken.decryptionJwk(),
                                                               "id-token.decryption-jwk",
                                                               "ID Token"),
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
        byte[] payload = jweDecryptor.decrypt(token, headers);
        try {
            return new OidcResolvedIdToken(token,
                                           true,
                                           SignedJwt.parseToken(new String(payload, StandardCharsets.UTF_8)));
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
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

    record OidcResolvedIdToken(String rawToken, boolean encrypted, SignedJwt signedJwt) {
    }
}
