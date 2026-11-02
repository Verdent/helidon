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
import java.util.Locale;
import java.util.Optional;

import io.helidon.common.Errors;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.JwtHeaders;
import io.helidon.security.jwt.JwtScope;
import io.helidon.security.jwt.JwtValidator;
import io.helidon.security.jwt.SignedJwt;

final class OidcJwtAccessTokenValidator implements OidcAccessTokenValidator {
    private static final String NONE_ALGORITHM = "none";

    OidcJwtAccessTokenValidator() {
    }

    @Override
    public OidcValidationResult<OidcValidatedAccessToken> validate(OidcAccessTokenValidationRequest request) {
        String token = request.token();
        OidcTenantContext tenantContext = request.tenantContext();
        OidcTokenValidationConfig tokenValidation = tenantContext.tokenValidation();
        JwtHeaders tokenHeaders;
        try {
            tokenHeaders = JwtHeaders.parseToken(token);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Bearer Token is not a valid JWT", e);
        }

        SignedJwt signedJwt;
        if (tokenHeaders.encryption().isPresent()) {
            try {
                signedJwt = decryptAccessToken(token, tokenHeaders, tenantContext, tokenValidation);
            } catch (RuntimeException e) {
                return OidcValidationResult.failure("Bearer Token JWE is invalid", e);
            }
        } else {
            if (tokenValidation.encryptionRequired().orElse(tokenValidation.decryptionJwk().isPresent())) {
                return OidcValidationResult.failure("Encrypted Bearer Token is required");
            }
            try {
                signedJwt = SignedJwt.parseToken(tokenHeaders, token);
            } catch (RuntimeException e) {
                return OidcValidationResult.failure("Bearer Token is not a valid signed JWT", e);
            }
        }

        Jwt jwt;
        try {
            jwt = signedJwt.getJwt();
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Bearer Token JWT payload is invalid", e);
        }

        if (tokenHeaders.encryption().isPresent() && !replicatedClaimsMatch(tokenHeaders, jwt)) {
            // RFC 7519, 5.3: do not accept contradictory claims replicated in the authenticated JWE header.
            return OidcValidationResult.failure("Bearer Token JWE headers contradict signed claims");
        }
        Errors headerErrors = headerValidator(tokenValidation).validate(jwt);
        if (!headerErrors.isValid()) {
            return OidcValidationResult.failure("Bearer Token JWS header is invalid");
        }

        try {
            Errors signatureErrors = OidcJoseKeyPolicy.verifySignature(
                    signedJwt,
                    jwt,
                    tenantContext.accessTokenJwkSetManager().jwkKeys(jwt.keyId()));
            if (!signatureErrors.isValid()) {
                return OidcValidationResult.failure("Bearer Token signature is invalid");
            }
        } catch (OidcJwkSetManager.UnavailableException e) {
            return OidcValidationResult.unavailable("Bearer Token signature keys are temporarily unavailable", e);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Bearer Token signature keys are unavailable", e);
        }

        OidcValidationResult<Boolean> confirmationValidation = OidcCertificateBoundAccessTokenSupport.validate(
                jwt.payloadClaimValue(OidcCertificateBoundAccessTokenSupport.CONFIRMATION_CLAIM),
                request);
        if (!confirmationValidation.succeeded()) {
            return OidcValidationResult.failure("Bearer Token JWT claims are invalid",
                                                confirmationValidation.cause().orElse(null));
        }

        Optional<String> expectedIssuer = tokenValidation.issuer().or(tenantContext.metadata()::issuer);
        if (expectedIssuer.isEmpty()) {
            return OidcValidationResult.failure("Bearer Token JWT validation is not configured");
        }
        Optional<String> expectedAudience = tokenValidation.audience();
        if (tokenValidation.audienceValidationEnabled() && expectedAudience.isEmpty()) {
            return OidcValidationResult.failure("Bearer Token JWT validation is not configured");
        }

        Errors claimErrors = claimValidator(tokenValidation,
                                            expectedIssuer.orElseThrow(),
                                            expectedAudience,
                                            request.validationTime()).validate(jwt);
        if (!claimErrors.isValid()) {
            return OidcValidationResult.failure("Bearer Token JWT claims are invalid");
        }
        // RFC 9068, 4: validation time must be strictly before exp, allowing configured clock skew.
        // The shared JWT expiration validator accepts equality, so reject that boundary here.
        if (jwt.expirationTime().orElseThrow().equals(request.validationTime().minus(tokenValidation.clockSkew()))) {
            return OidcValidationResult.failure("Bearer Token JWT claims are invalid");
        }
        try {
            OidcScopeSupport.validateScopeClaims(jwt.payloadClaimsJson(),
                                                 tenantContext.subjectMapping(),
                                                 "JWT access token");
        } catch (IllegalArgumentException e) {
            return OidcValidationResult.failure("Bearer Token JWT claims are invalid", e);
        }
        if (OidcSubjectMapper.principalId(jwt, tenantContext.subjectMapping()).isEmpty()) {
            return OidcValidationResult.failure("Bearer Token JWT cannot satisfy the configured principal mapping");
        }
        if (tenantContext.tenantConfig().adapter().isPresent()) {
            try {
                tenantContext.tenantConfig().adapter().orElseThrow()
                        .validateAccessToken(tenantContext.tenantConfig(), JsonObject.create(jwt.payloadClaimsJson()));
            } catch (RuntimeException e) {
                return OidcValidationResult.failure("Bearer Token JWT is rejected by OIDC adapter", e);
            }
        }

        return OidcValidationResult.success(new OidcValidatedJwt(token, signedJwt, jwt));
    }

    private SignedJwt decryptAccessToken(String token,
                                         JwtHeaders headers,
                                         OidcTenantContext tenantContext,
                                         OidcTokenValidationConfig tokenValidation) {
        // RFC 7519, 5.2: a signed-then-encrypted access token is a Nested JWT; the inner JWT must still be signed.
        if (headers.contentType().filter("JWT"::equalsIgnoreCase).isEmpty()) {
            throw new IllegalArgumentException("Encrypted Bearer Token must be a Nested JWT with cty=JWT");
        }
        if (headers.headerClaimValue("zip").isPresent()) {
            throw new IllegalArgumentException("Compressed Bearer Token JWE is not supported");
        }
        if (headers.algorithm().filter(tokenValidation.allowedEncryptionAlgorithms()::contains).isEmpty()
                || headers.encryption().filter(tokenValidation.allowedContentEncryptionAlgorithms()::contains).isEmpty()) {
            throw new IllegalArgumentException("Bearer Token JWE algorithm is not allowed");
        }
        OidcJweDecryptor decryptor = tenantContext.accessTokenDecryptor()
                .orElseThrow(() -> new IllegalArgumentException("Bearer Token decryption key is not configured"));
        byte[] payload = decryptor.decrypt(token, headers);
        try {
            String nestedToken = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(payload))
                    .toString();
            return SignedJwt.parseToken(nestedToken);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Bearer Token JWE plaintext is not UTF-8", e);
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
    }

    private boolean replicatedClaimsMatch(JwtHeaders headers, Jwt jwt) {
        // Only the signed inner claims are used for authentication; reject conflicting outer routing hints if present.
        return (headers.issuer().isEmpty() || headers.issuer().equals(jwt.issuer()))
                && (headers.subject().isEmpty() || headers.subject().equals(jwt.subject()))
                && (headers.audience().isEmpty() || headers.audience().equals(jwt.audience()));
    }

    private JwtValidator headerValidator(OidcTokenValidationConfig tokenValidation) {
        OidcJwtAccessTokenConfig layout = tokenValidation.jwt().orElseThrow();
        return JwtValidator.builder()
                .addCriticalValidator()
                .addValidator(JwtScope.HEADER, (jwt, collector) -> {
                    String algorithm = jwt.algorithm().orElse(null);
                    if (algorithm == null) {
                        collector.fatal(jwt, "JWT alg header is mandatory");
                    } else if (NONE_ALGORITHM.equalsIgnoreCase(algorithm)) {
                        /*
                         * Spec: RFC 9068, 2.1 Header and 4 Validation
                         * https://www.rfc-editor.org/rfc/rfc9068.html#section-2.1
                         * https://www.rfc-editor.org/rfc/rfc9068.html#section-4
                         * Quote: "JWT access tokens MUST NOT use \"none\" as the signing algorithm."
                         * Quote: "The resource server MUST reject any JWT in which the value of \"alg\" is \"none\"."
                         */
                        collector.fatal(jwt, "JWT alg header must not be none");
                    } else if (!tokenValidation.allowedAlgorithms().contains(algorithm)) {
                        collector.fatal(jwt, "JWT alg header is not allowed: " + algorithm);
                    }
                }, "alg")
                .addValidator(JwtScope.HEADER, (jwt, collector) -> {
                    String type = jwt.type().orElse(null);
                    if (type == null) {
                        /*
                         * RFC 8725, 3.12 permits mutually exclusive signed claim values to distinguish JWT kinds.
                         * A CUSTOM layout allowing a missing header must configure such a claim, checked below
                         * only after signature verification; RFC 9068 layouts always require the typ header.
                         * https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12
                         */
                        if (layout.typHeaderRequired()) {
                            collector.fatal(jwt, "JWT typ header is mandatory");
                        }
                    } else if (layout.allowedTypes().stream()
                            .map(allowed -> allowed.toLowerCase(Locale.ROOT))
                            .noneMatch(type.toLowerCase(Locale.ROOT)::equals)) {
                        collector.fatal(jwt, "JWT typ header is not an access token type: " + type);
                    }
                }, "typ")
                .build();
    }

    private JwtValidator claimValidator(OidcTokenValidationConfig tokenValidation,
                                        String expectedIssuer,
                                        Optional<String> expectedAudience,
                                        Instant validationTime) {
        OidcJwtAccessTokenConfig layout = tokenValidation.jwt().orElseThrow();
        boolean rfc9068 = layout.profile() == OidcJwtAccessTokenProfile.RFC_9068;
        JwtValidator.Builder builder = JwtValidator.builder()
                .addExpirationValidator(it -> it.now(validationTime)
                        .allowedTimeSkew(tokenValidation.clockSkew())
                        .mandatory(true))
                .addIssueTimeValidator(it -> it.now(validationTime)
                        .allowedTimeSkew(tokenValidation.clockSkew())
                        .mandatory(rfc9068 || layout.requiredClaims().contains("iat")))
                .addNotBeforeValidator(it -> it.now(validationTime).allowedTimeSkew(tokenValidation.clockSkew()))
                .addIssuerValidator(expectedIssuer);
        if (rfc9068) {
            builder.addValidator((jwt, collector) -> {
                    if (jwt.subject().filter(subject -> !subject.isBlank()).isEmpty()) {
                        collector.fatal(jwt, "JWT subject claim is mandatory");
                    }
                }, "sub")
                .addValidator((jwt, collector) -> {
                    if (jwt.jwtId().filter(jwtId -> !jwtId.isBlank()).isEmpty()) {
                        collector.fatal(jwt, "JWT jti claim is mandatory");
                    }
                }, "jti")
                .addValidator((jwt, collector) -> {
                    if (jwt.payloadClaimValue("client_id")
                            .filter(value -> value.type() == JsonValueType.STRING)
                            .map(value -> value.asString().value())
                            .filter(clientId -> !clientId.isBlank())
                            .isEmpty()) {
                        collector.fatal(jwt, "JWT client_id claim is mandatory");
                    }
                }, "client_id");
        }
        for (String claim : layout.requiredClaims()) {
            builder.addValidator((jwt, collector) -> {
                if (jwt.payloadClaimValue(claim)
                        .filter(value -> value.type() != JsonValueType.NULL)
                        .filter(value -> value.type() != JsonValueType.STRING || !value.asString().value().isBlank())
                        .isEmpty()) {
                    collector.fatal(jwt, "JWT " + claim + " claim is mandatory");
                }
            }, claim);
        }
        layout.requiredStringClaims().forEach((claim, expected) -> builder.addValidator((jwt, collector) -> {
            if (jwt.payloadClaimValue(claim)
                    .filter(value -> value.type() == JsonValueType.STRING)
                    .map(value -> value.asString().value())
                    .filter(expected::equals)
                    .isEmpty()) {
                collector.fatal(jwt, "JWT " + claim + " claim does not match the required access-token value");
            }
        }, claim));
        if (tokenValidation.audienceValidationEnabled()) {
            expectedAudience.ifPresent(builder::addAudienceValidator);
        }
        return builder.build();
    }
}
