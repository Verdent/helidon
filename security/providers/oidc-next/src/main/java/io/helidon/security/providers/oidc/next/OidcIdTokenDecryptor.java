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

    private OidcIdTokenDecryptor(Optional<JwkKeys> decryptionKeys, boolean encryptionRequired) {
        this.decryptionKeys = decryptionKeys;
        this.encryptionRequired = encryptionRequired;
    }

    static OidcIdTokenDecryptor create(OidcTenantConfig tenantConfig) {
        OidcIdTokenConfig idToken = tenantConfig.idToken();
        return new OidcIdTokenDecryptor(idToken.decryptionJwk()
                                                .map(OidcIdTokenDecryptor::loadKeys),
                                        idToken.encryptionRequired());
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

        JwkKeys keys = decryptionKeys.orElseThrow(() -> new IllegalStateException(
                "ID Token decryption keys are not configured"));
        EncryptedJwt encryptedJwt = EncryptedJwt.parseToken(headers, token);
        return new OidcResolvedIdToken(token, true, encryptedJwt.decrypt(keys, keys.keys().getFirst()));
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
