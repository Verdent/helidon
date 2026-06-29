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
import java.util.Optional;

import io.helidon.common.Errors;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.JwtScope;
import io.helidon.security.jwt.JwtValidator;
import io.helidon.security.jwt.SignedJwt;

final class OidcUserInfoJwtValidator {
    private static final String NONE_ALGORITHM = "none";

    OidcUserInfoJwtValidator() {
    }

    OidcValidationResult<JsonObject> validate(String token,
                                              OidcTenantContext tenantContext,
                                              OidcValidatedIdToken idToken,
                                              OidcUserInfoJwtConfig config) {
        SignedJwt signedJwt;
        try {
            signedJwt = SignedJwt.parseToken(token);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("UserInfo response is not a valid signed JWT", e);
        }
        return validate(signedJwt, tenantContext, idToken, config);
    }

    OidcValidationResult<JsonObject> validate(SignedJwt signedJwt,
                                              OidcTenantContext tenantContext,
                                              OidcValidatedIdToken idToken,
                                              OidcUserInfoJwtConfig config) {
        Jwt jwt;
        try {
            jwt = signedJwt.getJwt();
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("UserInfo JWT payload is invalid", e);
        }

        Errors headerErrors = headerValidator(config).validate(jwt);
        if (!headerErrors.isValid()) {
            return OidcValidationResult.failure("UserInfo JWT header is invalid");
        }

        try {
            Errors signatureErrors = signedJwt.verifySignature(tenantContext.jwkSetManager().jwkKeys(jwt.keyId()));
            if (!signatureErrors.isValid()) {
                return OidcValidationResult.failure("UserInfo JWT signature is invalid");
            }
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("UserInfo JWT signature keys are unavailable", e);
        }

        Optional<String> expectedIssuer = tenantContext.metadata()
                .issuer();
        Optional<String> clientId = tenantContext.tenantConfig().clientId();
        if (expectedIssuer.isEmpty() || clientId.isEmpty()) {
            return OidcValidationResult.failure("UserInfo JWT validation is not configured");
        }

        Errors claimErrors = claimValidator(expectedIssuer.orElseThrow(),
                                            clientId.orElseThrow(),
                                            idToken,
                                            config).validate(jwt);
        if (!claimErrors.isValid()) {
            return OidcValidationResult.failure("UserInfo JWT claims are invalid");
        }
        return OidcValidationResult.success(jwt.payloadJsonObject());
    }

    private JwtValidator headerValidator(OidcUserInfoJwtConfig config) {
        String expectedAlgorithm = config.signingAlgorithm().orElseThrow();
        return JwtValidator.builder()
                .addCriticalValidator()
                .addValidator(JwtScope.HEADER, (jwt, collector) -> {
                    String algorithm = jwt.algorithm().orElse(null);
                    if (algorithm == null) {
                        collector.fatal(jwt, "JWT alg header is mandatory");
                    } else if (NONE_ALGORITHM.equalsIgnoreCase(algorithm)) {
                        collector.fatal(jwt, "JWT alg header must not be none");
                    } else if (!expectedAlgorithm.equals(algorithm)) {
                        collector.fatal(jwt, "JWT alg header does not match registered UserInfo algorithm");
                    }
                }, "alg")
                .build();
    }

    private JwtValidator claimValidator(String expectedIssuer,
                                        String clientId,
                                        OidcValidatedIdToken idToken,
                                        OidcUserInfoJwtConfig config) {
        /*
         * Spec: OpenID Connect Core 1.0, 5.3.2 Successful UserInfo Response
         * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
         * Quote: "If signed, the UserInfo Response MUST contain the Claims iss (issuer) and aud (audience) as members."
         * Quote: "The iss value MUST be the OP's Issuer Identifier URL."
         * Quote: "The aud value MUST be or include the RP's Client ID value."
         */
        Instant now = Instant.now();
        return JwtValidator.builder()
                .addExpirationValidator(it -> it.now(now)
                        .allowedTimeSkew(config.clockSkew())
                        .mandatory(false))
                .addIssueTimeValidator(it -> it.now(now)
                        .allowedTimeSkew(config.clockSkew())
                        .mandatory(false))
                .addNotBeforeValidator(it -> it.now(now)
                        .allowedTimeSkew(config.clockSkew()))
                .addIssuerValidator(expectedIssuer)
                .addAudienceValidator(clientId)
                .addValidator((jwt, collector) -> validateSubject(jwt, idToken, collector), "sub")
                .build();
    }

    private void validateSubject(Jwt jwt, OidcValidatedIdToken idToken, Errors.Collector collector) {
        /*
         * Spec: OpenID Connect Core 1.0, 5.3.2 Successful UserInfo Response
         * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
         * Quote: "The sub (subject) Claim MUST always be returned in the UserInfo Response."
         * Quote: "The sub Claim in the UserInfo Response MUST be verified to exactly match the sub Claim in the ID
         * Token; if they do not match, the UserInfo Response values MUST NOT be used."
         */
        Optional<String> userInfoSubject = jwt.subject()
                .filter(subject -> !subject.isBlank());
        if (userInfoSubject.isEmpty()) {
            collector.fatal(jwt, "JWT subject claim is mandatory");
            return;
        }
        String idTokenSubject = idToken.jwt()
                .subject()
                .orElseThrow();
        if (!idTokenSubject.equals(userInfoSubject.orElseThrow())) {
            collector.fatal(jwt, "JWT subject claim must match ID Token subject");
        }
    }
}
