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
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.JwtScope;
import io.helidon.security.jwt.JwtValidator;
import io.helidon.security.jwt.SignedJwt;

final class OidcJwtAccessTokenValidator {
    private static final List<String> ALLOWED_ACCESS_TOKEN_TYPES = List.of("at+jwt", "application/at+jwt");

    private OidcJwtAccessTokenValidator() {
    }

    static OidcJwtAccessTokenValidator create() {
        return new OidcJwtAccessTokenValidator();
    }

    OidcTokenValidationResult validate(String token, OidcTenantContext tenantContext) {
        SignedJwt signedJwt;
        try {
            signedJwt = SignedJwt.parseToken(token);
        } catch (RuntimeException e) {
            return OidcTokenValidationResult.failure("Bearer Token is not a valid signed JWT", e);
        }

        Jwt jwt;
        try {
            jwt = signedJwt.getJwt();
        } catch (RuntimeException e) {
            return OidcTokenValidationResult.failure("Bearer Token JWT payload is invalid", e);
        }

        OidcTokenValidationPolicy policy = tenantContext.tokenValidationPolicy();
        Errors headerErrors = headerValidator(policy.allowedAlgorithms()).validate(jwt);
        if (!headerErrors.isValid()) {
            return OidcTokenValidationResult.failure("Bearer Token JWS header is invalid");
        }

        try {
            Errors signatureErrors = signedJwt.verifySignature(tenantContext.jwkSetManager().jwkKeys());
            if (!signatureErrors.isValid()) {
                return OidcTokenValidationResult.failure("Bearer Token signature is invalid");
            }
        } catch (RuntimeException e) {
            return OidcTokenValidationResult.failure("Bearer Token signature keys are unavailable", e);
        }

        Optional<String> expectedIssuer = tenantContext.metadata().issuer().map(Object::toString);
        if (expectedIssuer.isEmpty()) {
            return OidcTokenValidationResult.failure("Bearer Token JWT validation is not configured");
        }
        Optional<String> expectedAudience = policy.audience();
        if (policy.audienceValidationEnabled() && expectedAudience.isEmpty()) {
            return OidcTokenValidationResult.failure("Bearer Token JWT validation is not configured");
        }

        Errors claimErrors = claimValidator(policy, expectedIssuer.get(), expectedAudience).validate(jwt);
        if (!claimErrors.isValid()) {
            return OidcTokenValidationResult.failure("Bearer Token JWT claims are invalid");
        }

        return OidcTokenValidationResult.success(OidcValidatedJwt.create(token, signedJwt, jwt));
    }

    private JwtValidator headerValidator(List<String> allowedAlgorithms) {
        return JwtValidator.builder()
                .addCriticalValidator()
                .addValidator(JwtScope.HEADER, (jwt, collector) -> {
                    String algorithm = jwt.algorithm().orElse(null);
                    if (algorithm == null) {
                        collector.fatal(jwt, "JWT alg header is mandatory");
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

    private JwtValidator claimValidator(OidcTokenValidationPolicy policy,
                                        String expectedIssuer,
                                        Optional<String> expectedAudience) {
        Instant now = Instant.now();
        JwtValidator.Builder builder = JwtValidator.builder()
                .addExpirationValidator(it -> it.now(now).allowedTimeSkew(policy.clockSkew()).mandatory(true))
                .addIssueTimeValidator(it -> it.now(now).allowedTimeSkew(policy.clockSkew()))
                .addNotBeforeValidator(it -> it.now(now).allowedTimeSkew(policy.clockSkew()))
                .addIssuerValidator(expectedIssuer)
                .addValidator((jwt, collector) -> {
                    if (jwt.subject().filter(subject -> !subject.isBlank()).isEmpty()) {
                        collector.fatal(jwt, "JWT subject claim is mandatory");
                    }
                }, "sub");
        if (policy.audienceValidationEnabled()) {
            builder.addAudienceValidator(expectedAudience.orElseThrow());
        }
        return builder.build();
    }
}
