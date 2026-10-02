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

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

import io.helidon.common.Errors;
import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.Jwt;
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
        SignedJwt signedJwt;
        try {
            signedJwt = SignedJwt.parseToken(token);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Bearer Token is not a valid signed JWT", e);
        }

        Jwt jwt;
        try {
            jwt = signedJwt.getJwt();
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Bearer Token JWT payload is invalid", e);
        }

        OidcTokenValidationConfig tokenValidation = tenantContext.tokenValidation();
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

        Optional<String> expectedIssuer = tenantContext.metadata()
                .issuer();
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
        try {
            OidcScopeSupport.validateScopeClaims(jwt.payloadClaimsJson(),
                                                 tenantContext.subjectMapping(),
                                                 "JWT access token");
        } catch (IllegalArgumentException e) {
            return OidcValidationResult.failure("Bearer Token JWT claims are invalid", e);
        }
        // Browser refresh retains the ID Token identity; only an incoming API token must map to an API principal.
        if (request.protectedResource() && OidcSubjectMapper.principalId(jwt, tenantContext.subjectMapping()).isEmpty()) {
            return OidcValidationResult.failure("Bearer Token JWT cannot satisfy the configured principal mapping");
        }

        return OidcValidationResult.success(new OidcValidatedJwt(token, signedJwt, jwt));
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
