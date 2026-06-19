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
import java.util.List;
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
    private static final List<String> ALLOWED_ACCESS_TOKEN_TYPES = List.of("at+jwt", "application/at+jwt");

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
        Errors headerErrors = headerValidator(tokenValidation.allowedAlgorithms()).validate(jwt);
        if (!headerErrors.isValid()) {
            return OidcValidationResult.failure("Bearer Token JWS header is invalid");
        }

        try {
            Errors signatureErrors = signedJwt.verifySignature(tenantContext.jwkSetManager().jwkKeys(jwt.keyId()));
            if (!signatureErrors.isValid()) {
                return OidcValidationResult.failure("Bearer Token signature is invalid");
            }
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
                                            expectedAudience).validate(jwt);
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
        if (OidcSubjectMapper.principalId(jwt, tenantContext.subjectMapping()).isEmpty()) {
            return OidcValidationResult.failure("Bearer Token JWT has no principal claim");
        }

        return OidcValidationResult.success(new OidcValidatedJwt(token, signedJwt, jwt));
    }

    private JwtValidator headerValidator(List<String> allowedAlgorithms) {
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
                    } else if (!allowedAlgorithms.contains(algorithm)) {
                        collector.fatal(jwt, "JWT alg header is not allowed: " + algorithm);
                    }
                }, "alg")
                .addValidator(JwtScope.HEADER, (jwt, collector) -> {
                    String type = jwt.type().orElse(null);
                    if (type == null) {
                        collector.fatal(jwt, "JWT typ header is mandatory");
                    } else if (!ALLOWED_ACCESS_TOKEN_TYPES.contains(type.toLowerCase(Locale.ROOT))) {
                        collector.fatal(jwt, "JWT typ header is not an access token type: " + type);
                    }
                }, "typ")
                .build();
    }

    private JwtValidator claimValidator(OidcTokenValidationConfig tokenValidation,
                                        String expectedIssuer,
                                        Optional<String> expectedAudience) {
        Instant now = Instant.now();
        JwtValidator.Builder builder = JwtValidator.builder()
                .addExpirationValidator(it -> it.now(now).allowedTimeSkew(tokenValidation.clockSkew()).mandatory(true))
                .addIssueTimeValidator(it -> it.now(now).allowedTimeSkew(tokenValidation.clockSkew()).mandatory(true))
                .addNotBeforeValidator(it -> it.now(now).allowedTimeSkew(tokenValidation.clockSkew()))
                .addIssuerValidator(expectedIssuer)
                .addValidator((jwt, collector) -> {
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
        if (tokenValidation.audienceValidationEnabled()) {
            expectedAudience.ifPresent(builder::addAudienceValidator);
        }
        return builder.build();
    }
}
