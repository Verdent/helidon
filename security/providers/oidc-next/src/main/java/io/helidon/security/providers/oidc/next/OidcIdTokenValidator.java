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
import java.util.Optional;

import io.helidon.common.Errors;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.JwtScope;
import io.helidon.security.jwt.JwtValidator;
import io.helidon.security.jwt.SignedJwt;

final class OidcIdTokenValidator {
    private static final String NONE_ALGORITHM = "none";
    private static final String AUTHORIZED_PARTY_CLAIM = "azp";
    private static final String AUTHENTICATION_TIME_CLAIM = "auth_time";

    private OidcIdTokenValidator() {
    }

    static OidcIdTokenValidator create() {
        return new OidcIdTokenValidator();
    }

    OidcValidationResult<OidcValidatedIdToken> validate(String token,
                                                        OidcTenantContext tenantContext,
                                                        OidcAuthenticationRequestState authenticationRequestState) {
        return validate(token, tenantContext, Optional.of(authenticationRequestState.nonce()));
    }

    OidcValidationResult<OidcValidatedIdToken> validateRefresh(String token,
                                                               OidcTenantContext tenantContext,
                                                               OidcValidatedIdToken currentIdToken) {
        OidcValidationResult<OidcValidatedIdToken> validationResult = validate(token, tenantContext, Optional.empty());
        if (!validationResult.succeeded()) {
            return validationResult;
        }

        Jwt current = currentIdToken.jwt();
        Jwt refreshed = validationResult.validatedToken().orElseThrow().jwt();
        /*
         * Spec: OpenID Connect Core 1.0, 12.2 Successful Refresh Response
         * https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
         * Quotes: "If an ID Token is returned as a result of a token refresh request"; "`iss` Claim Value MUST be the
         * same as in the ID Token issued when the original authentication occurred"; "`sub` Claim Value MUST be the
         * same"; "`aud` Claim Value MUST be the same"; "`azp` Claim Value MUST be the same"; "`auth_time` Claim,
         * its value MUST represent the time of the original authentication"; "its `nonce` Claim Value SHOULD NOT be
         * present. If present, its value MUST be the same as in the ID Token issued when the original authentication
         * occurred".
         */
        if (!refreshed.issuer().equals(current.issuer())) {
            return OidcValidationResult.failure(
                    "Refreshed ID Token issuer does not match the existing local authentication result");
        }
        if (!refreshed.subject().equals(current.subject())) {
            return OidcValidationResult.failure(
                    "Refreshed ID Token subject does not match the existing local authentication result");
        }
        if (!refreshed.audience().equals(current.audience())) {
            return OidcValidationResult.failure(
                    "Refreshed ID Token audience does not match the existing local authentication result");
        }
        if (!refreshed.payloadClaimValue(AUTHORIZED_PARTY_CLAIM).map(JsonValue::toString)
                .equals(current.payloadClaimValue(AUTHORIZED_PARTY_CLAIM).map(JsonValue::toString))) {
            return OidcValidationResult.failure(
                    "Refreshed ID Token authorized party does not match the existing local authentication result");
        }
        if (refreshed.nonce().isPresent() && !refreshed.nonce().equals(current.nonce())) {
            return OidcValidationResult.failure(
                    "Refreshed ID Token nonce does not match the existing local authentication result");
        }
        Optional<String> refreshedAuthenticationTime = refreshed.payloadClaimValue(AUTHENTICATION_TIME_CLAIM)
                .map(JsonValue::toString);
        if (refreshedAuthenticationTime.isPresent()
                && !refreshedAuthenticationTime.equals(current.payloadClaimValue(AUTHENTICATION_TIME_CLAIM)
                                                               .map(JsonValue::toString))) {
            return OidcValidationResult.failure(
                    "Refreshed ID Token authentication time does not match the existing local authentication result");
        }

        return validationResult;
    }

    private OidcValidationResult<OidcValidatedIdToken> validate(String token,
                                                               OidcTenantContext tenantContext,
                                                               Optional<String> expectedNonce) {
        OidcIdTokenDecryptor.OidcResolvedIdToken resolvedIdToken;
        try {
            resolvedIdToken = tenantContext.idTokenDecryptor().resolve(token);
        } catch (IllegalStateException e) {
            return OidcValidationResult.failure(e.getMessage(), e);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("ID Token is not a valid signed or encrypted JWT", e);
        }

        SignedJwt signedJwt = resolvedIdToken.signedJwt();
        Jwt jwt;
        try {
            jwt = signedJwt.getJwt();
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("ID Token JWT payload is invalid", e);
        }

        OidcIdTokenConfig idToken = tenantContext.tenantConfig().idToken();
        Errors headerErrors = headerValidator(idToken.allowedAlgorithms()).validate(jwt);
        if (!headerErrors.isValid()) {
            return OidcValidationResult.failure("ID Token JWS header is invalid");
        }

        try {
            /*
             * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
             * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
             * Quotes: "The Client MUST validate the signature of all other ID Tokens according to JWS [JWS]";
             * "The Client MUST use the keys provided by the Issuer".
             */
            Errors signatureErrors = signedJwt.verifySignature(tenantContext.jwkSetManager().jwkKeys(jwt.keyId()));
            if (!signatureErrors.isValid()) {
                return OidcValidationResult.failure("ID Token signature is invalid");
            }
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("ID Token signature keys are unavailable", e);
        }

        Optional<String> expectedIssuer = tenantContext.metadata()
                .issuer();
        Optional<String> clientId = tenantContext.tenantConfig().clientId();
        if (expectedIssuer.isEmpty() || clientId.isEmpty()) {
            return OidcValidationResult.failure("ID Token validation is not configured");
        }

        Errors claimErrors = claimValidator(idToken,
                                            expectedIssuer.orElseThrow(),
                                            clientId.orElseThrow(),
                                            expectedNonce).validate(jwt);
        if (!claimErrors.isValid()) {
            return OidcValidationResult.failure("ID Token claims are invalid");
        }

        return OidcValidationResult.success(OidcValidatedIdToken.create(resolvedIdToken.rawToken(),
                                                                        resolvedIdToken.encrypted(),
                                                                        signedJwt,
                                                                        jwt));
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
                         * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
                         * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                         * Quotes: "The Client MUST validate the signature of all other ID Tokens according to JWS";
                         * "The Client MUST use the keys provided by the Issuer".
                         */
                        collector.fatal(jwt, "JWT alg header must not be none");
                    } else if (!allowedAlgorithms.contains(algorithm)) {
                        collector.fatal(jwt, "JWT alg header is not allowed: " + algorithm);
                    }
                }, "alg")
                .build();
    }

    private JwtValidator claimValidator(OidcIdTokenConfig idToken,
                                        String expectedIssuer,
                                        String clientId,
                                        Optional<String> expectedNonce) {
        /*
         * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
         * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
         * Quotes: "MUST exactly match the value of the iss (issuer) Claim";
         * "The Client MUST validate that the aud (audience) Claim contains its client_id value";
         * "additional audiences not trusted by the Client";
         * "If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present";
         * "If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim
         * Value"; "The current time MUST be before the time represented by the exp Claim";
         * "iat REQUIRED. Time at which the JWT was issued"; "If a nonce value was sent in the Authentication Request,
         * a nonce Claim MUST be present and its value checked".
         */
        Instant now = Instant.now();
        return JwtValidator.builder()
                .addExpirationValidator(it -> it.now(now).allowedTimeSkew(idToken.clockSkew()).mandatory(true))
                .addIssueTimeValidator(it -> it.now(now).allowedTimeSkew(idToken.clockSkew()).mandatory(true))
                .addNotBeforeValidator(it -> it.now(now).allowedTimeSkew(idToken.clockSkew()))
                .addIssuerValidator(expectedIssuer)
                .addAudienceValidator(clientId)
                .addValidator((jwt, collector) -> {
                    /*
                     * Spec: OpenID Connect Core 1.0, 2 ID Token
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDToken
                     * Quote: "REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the
                     * Issuer for the End-User".
                     */
                    if (jwt.subject().filter(subject -> !subject.isBlank()).isEmpty()) {
                        collector.fatal(jwt, "JWT subject claim is mandatory");
                    }
                }, "sub")
                .addValidator((jwt, collector) -> validateNonce(jwt, expectedNonce, collector), "nonce")
                .addValidator((jwt, collector) -> validateAudience(jwt,
                                                                    clientId,
                                                                    idToken.trustedAdditionalAudiences(),
                                                                    collector),
                              "aud", "azp")
                .build();
    }

    private void validateNonce(Jwt jwt, Optional<String> expectedNonce, Errors.Collector collector) {
        if (expectedNonce.isEmpty()) {
            return;
        }
        Optional<String> nonce = jwt.nonce();
        if (nonce.isEmpty()) {
            collector.fatal(jwt, "JWT nonce claim is mandatory");
            return;
        }
        if (!expectedNonce.orElseThrow().equals(nonce.orElseThrow())) {
            collector.fatal(jwt, "JWT nonce claim does not match the Authentication Request nonce");
        }
    }

    private void validateAudience(Jwt jwt,
                                  String clientId,
                                  List<String> trustedAdditionalAudiences,
                                  Errors.Collector collector) {
        Optional<List<String>> audiences = jwt.audience();
        Optional<String> authorizedParty = authorizedParty(jwt, collector);
        if (audiences.filter(values -> values.size() > 1).isPresent() && authorizedParty.isEmpty()) {
            collector.fatal(jwt, "JWT authorized party claim is mandatory when multiple audiences are present");
            return;
        }
        authorizedParty.filter(value -> !clientId.equals(value))
                .ifPresent(value -> collector.fatal(jwt, "JWT authorized party claim does not match client id"));
        audiences.stream()
                .flatMap(List::stream)
                .filter(audience -> !clientId.equals(audience))
                .filter(audience -> !trustedAdditionalAudiences.contains(audience))
                .findFirst()
                .ifPresent(audience -> collector.fatal(
                        jwt,
                        "JWT audience contains an untrusted additional audience: " + audience));
    }

    private Optional<String> authorizedParty(Jwt jwt, Errors.Collector collector) {
        Optional<JsonValue> claim = jwt.payloadClaimValue(AUTHORIZED_PARTY_CLAIM);
        if (claim.isEmpty()) {
            return Optional.empty();
        }
        JsonValue value = claim.orElseThrow();
        if (value.type() != JsonValueType.STRING) {
            collector.fatal(jwt, "JWT authorized party claim must be a string");
            return Optional.empty();
        }
        String authorizedParty = value.asString().value();
        if (authorizedParty.isBlank()) {
            collector.fatal(jwt, "JWT authorized party claim must not be blank");
            return Optional.empty();
        }
        return Optional.of(authorizedParty);
    }

}
