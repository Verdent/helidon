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

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.JwtHeaders;
import io.helidon.security.jwt.SignedJwt;

final class OidcUserInfoJwtProcessor {
    private static final OidcUserInfoJwtValidator SIGNED_JWT_VALIDATOR = new OidcUserInfoJwtValidator();

    private final OidcUserInfoJwtConfig config;
    private final OidcJweDecryptor jweDecryptor;

    private OidcUserInfoJwtProcessor(OidcUserInfoJwtConfig config, OidcJweDecryptor jweDecryptor) {
        this.config = config;
        this.jweDecryptor = jweDecryptor;
    }

    static Optional<OidcUserInfoJwtProcessor> create(OidcTenantConfig tenantConfig) {
        return tenantConfig.userInfo()
                .flatMap(OidcUserInfoConfig::jwt)
                .map(config -> new OidcUserInfoJwtProcessor(
                        config,
                        OidcJweDecryptor.create(config.decryptionJwk(),
                                                "user-info.jwt.decryption-jwk",
                                                "UserInfo response")));
    }

    OidcValidationResult<JsonObject> validate(String token,
                                              OidcTenantContext tenantContext,
                                              OidcValidatedIdToken idToken,
                                              Instant validationTime) {
        Objects.requireNonNull(validationTime);
        JwtHeaders headers;
        try {
            headers = JwtHeaders.parseToken(token);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("UserInfo response is not a valid JWT", e);
        }

        if (config.encryptionAlgorithm().isEmpty()) {
            if (headers.encryption().isPresent()) {
                return OidcValidationResult.failure("Encrypted UserInfo response was not registered");
            }
            return SIGNED_JWT_VALIDATOR.validate(token, tenantContext, idToken, config, validationTime);
        }
        if (headers.encryption().isEmpty()) {
            return OidcValidationResult.failure("Registered encrypted UserInfo response is not encrypted");
        }
        return validateEncrypted(token, headers, tenantContext, idToken, validationTime);
    }

    private OidcValidationResult<JsonObject> validateEncrypted(String token,
                                                               JwtHeaders headers,
                                                               OidcTenantContext tenantContext,
                                                               OidcValidatedIdToken idToken,
                                                               Instant validationTime) {
        String expectedAlgorithm = config.encryptionAlgorithm().orElseThrow();
        if (headers.algorithm().filter(expectedAlgorithm::equals).isEmpty()) {
            return OidcValidationResult.failure("UserInfo JWE alg header does not match registration");
        }
        String expectedContentEncryption = config.contentEncryptionAlgorithm()
                .orElse(OidcUserInfoJwtConfigBlueprint.DEFAULT_CONTENT_ENCRYPTION_ALGORITHM);
        if (headers.encryption().filter(expectedContentEncryption::equals).isEmpty()) {
            return OidcValidationResult.failure("UserInfo JWE enc header does not match registration");
        }
        if (headers.critical().filter(critical -> !critical.isEmpty()).isPresent()) {
            return OidcValidationResult.failure("UserInfo JWE contains unsupported critical headers");
        }

        boolean signed = config.signingAlgorithm().isPresent();
        boolean nestedJwt = headers.contentType().filter("JWT"::equalsIgnoreCase).isPresent();
        /*
         * Spec: OpenID Connect Core 1.0, 5.3.2 Successful UserInfo Response
         * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
         * Quote: "The response MAY be encrypted without also being signed. If both signing and encryption are
         * requested, the response MUST be signed then encrypted, with the result being a Nested JWT."
         */
        if (signed && !nestedJwt) {
            /*
             * Spec: RFC 7519, 5.2 cty Header Parameter
             * https://www.rfc-editor.org/rfc/rfc7519.html#section-5.2
             * Quote: "In the case that nested signing or encryption is employed, this Header Parameter MUST be
             * present; in this case, the value MUST be `JWT`."
             */
            return OidcValidationResult.failure("Nested UserInfo JWT must use cty=JWT");
        }
        if (!signed && nestedJwt) {
            return OidcValidationResult.failure("Encryption-only UserInfo response must not identify a Nested JWT");
        }

        byte[] payload;
        try {
            payload = jweDecryptor.decrypt(token, headers);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("UserInfo JWE decryption failed", e);
        }
        try {
            String decodedPayload = decodeUtf8(payload);
            if (signed) {
                SignedJwt signedJwt = SignedJwt.parseToken(decodedPayload);
                return SIGNED_JWT_VALIDATOR.validate(signedJwt,
                                                     tenantContext,
                                                     idToken,
                                                     config,
                                                     validationTime);
            }
            JsonObject claims = JsonParser.create(decodedPayload).readJsonObject();
            return OidcValidationResult.success(claims);
        } catch (CharacterCodingException | RuntimeException e) {
            return OidcValidationResult.failure("UserInfo JWE payload is invalid", e);
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
    }

    private static String decodeUtf8(byte[] payload) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(payload))
                .toString();
    }
}
