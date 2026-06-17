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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.Optional;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;

final class OidcCertificateBoundAccessTokenSupport {
    static final String CONFIRMATION_CLAIM = "cnf";
    static final String DPOP_JWK_THUMBPRINT_CONFIRMATION = "jkt";
    static final String X509_CERTIFICATE_THUMBPRINT_CONFIRMATION = "x5t#S256";

    private OidcCertificateBoundAccessTokenSupport() {
    }

    static OidcValidationResult<Boolean> validate(Optional<JsonValue> confirmationClaim,
                                                  OidcAccessTokenValidationRequest request) {
        Optional<JsonObject> confirmation = confirmationClaim
                .filter(value -> value.type() == JsonValueType.OBJECT)
                .map(value -> value.asObject());
        if (confirmation.flatMap(value -> value.value(DPOP_JWK_THUMBPRINT_CONFIRMATION)).isPresent()) {
            /*
             * Spec: RFC 9449, 7.2 Checking DPoP Proofs
             * https://www.rfc-editor.org/rfc/rfc9449.html#section-7.2
             * Quote: "MUST reject a DPoP-bound access token received as a bearer token".
             */
            return OidcValidationResult.failure("Bearer Token confirmation claim is invalid");
        }

        Optional<JsonValue> thumbprintValue = confirmation
                .flatMap(value -> value.value(X509_CERTIFICATE_THUMBPRINT_CONFIRMATION));
        OidcCertificateBoundAccessTokenMode mode = request.tenantContext()
                .tokenValidation()
                .certificateBoundAccessTokens()
                .mode();
        if (!request.protectedResource() || mode == OidcCertificateBoundAccessTokenMode.DISABLED) {
            return thumbprintValue.isPresent()
                    ? OidcValidationResult.failure("Bearer Token confirmation claim is invalid")
                    : OidcValidationResult.success(Boolean.TRUE);
        }
        if (thumbprintValue.isEmpty()) {
            return mode == OidcCertificateBoundAccessTokenMode.REQUIRED
                    ? OidcValidationResult.failure("Bearer Token confirmation claim is invalid")
                    : OidcValidationResult.success(Boolean.TRUE);
        }

        JsonValue value = thumbprintValue.orElseThrow();
        if (value.type() != JsonValueType.STRING) {
            return OidcValidationResult.failure("Bearer Token confirmation claim is invalid");
        }
        String expectedThumbprint = value.asString().value();
        if (!validSha256Base64UrlThumbprint(expectedThumbprint)) {
            return OidcValidationResult.failure("Bearer Token confirmation claim is invalid");
        }
        Optional<Certificate> peerCertificate = request.peerCertificate();
        if (peerCertificate.isEmpty()) {
            return OidcValidationResult.failure("Bearer Token confirmation claim is invalid");
        }
        /*
         * Spec: RFC 8705, 3 Mutual-TLS Certificate-Bound Access Tokens
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-3
         * Quote: "MUST obtain, from its TLS implementation layer, the client certificate used for mutual TLS".
         * Quote: "MUST verify that the certificate matches the certificate associated with the access token."
         */
        String actualThumbprint;
        try {
            /*
             * Spec: RFC 8705, 3.1 JWT Certificate Thumbprint Confirmation Method
             * https://www.rfc-editor.org/rfc/rfc8705.html#section-3.1
             * Quote: "The value of the `x5t#S256` member is a base64url-encoded [RFC4648] SHA-256 [SHS] hash
             * (a.k.a., thumbprint, fingerprint, or digest) of the DER encoding [X690] of the X.509 certificate
             * [RFC5280]."
             * Quote: "MUST omit all trailing pad '=' characters and MUST NOT include any line breaks, whitespace, or
             * other additional characters."
             */
            actualThumbprint = certificateThumbprint(peerCertificate.orElseThrow());
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            return OidcValidationResult.failure("Bearer Token confirmation claim is invalid", e);
        }
        if (!expectedThumbprint.equals(actualThumbprint)) {
            return OidcValidationResult.failure("Bearer Token confirmation claim is invalid");
        }
        return OidcValidationResult.success(Boolean.TRUE);
    }

    private static boolean validSha256Base64UrlThumbprint(String value) {
        if (value.length() != 43 || value.indexOf('=') >= 0) {
            return false;
        }
        try {
            return Base64.getUrlDecoder().decode(value).length == 32;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String certificateThumbprint(Certificate certificate)
            throws CertificateEncodingException, NoSuchAlgorithmException {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    }
}
