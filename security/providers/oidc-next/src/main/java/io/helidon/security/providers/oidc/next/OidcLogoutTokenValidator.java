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
import java.util.Set;

import io.helidon.common.Errors;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.JwtScope;
import io.helidon.security.jwt.JwtValidator;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;

/**
 * Validates an OP-issued Logout Token without mistaking it for an ID Token or bearer access token.
 */
final class OidcLogoutTokenValidator {
    private static final String LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
    private static final Set<String> ACCEPTED_TYPES = Set.of("jwt", "application/jwt", "logout+jwt", "application/logout+jwt");
    private static final int MAX_SUBJECT_LENGTH = 255;

    private final OidcIdTokenValidator idTokenValidator = new OidcIdTokenValidator();

    OidcValidationResult<OidcBackChannelLogoutStore.LogoutEvent> validate(String token,
                                                                           OidcTenantContext tenant,
                                                                           Instant now) {
        SignedJwt signedJwt;
        Jwt jwt;
        try {
            // Back-Channel Logout 2.6 uses the ID Token's negotiated encryption keys/algorithms, but has different
            // claim requirements: a Logout Token may be sid-only and MUST NOT contain a nonce.
            signedJwt = tenant.idTokenDecryptor().resolve(token).signedJwt();
            jwt = signedJwt.getJwt();
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Logout Token is not a valid signed or encrypted JWT", e);
        }

        OidcIdTokenConfig idToken = tenant.tenantConfig().idToken();
        if (!headerValidator(idToken.allowedAlgorithms()).validate(jwt).isValid()) {
            return OidcValidationResult.failure("Logout Token JWS header is invalid");
        }
        try {
            Errors signature = OidcJoseKeyPolicy.verifySignature(signedJwt,
                                                                 jwt,
                                                                 tenant.jwkSetManager().jwkKeys(jwt.keyId()));
            if (!signature.isValid()) {
                return OidcValidationResult.failure("Logout Token signature is invalid");
            }
        } catch (OidcJwkSetManager.UnavailableException e) {
            return OidcValidationResult.unavailable("Logout Token verification keys are unavailable", e);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Logout Token signature cannot be verified", e);
        }

        Optional<String> expectedIssuer = tenant.metadata().issuer();
        Optional<String> clientId = tenant.tenantConfig().clientId();
        if (expectedIssuer.isEmpty() || clientId.isEmpty()) {
            return OidcValidationResult.failure("Logout Token validation is not configured");
        }
        if (!claimsValidator(idToken,
                             expectedIssuer.orElseThrow(),
                             clientId.orElseThrow(),
                             now).validate(jwt).isValid()) {
            return OidcValidationResult.failure("Logout Token claims are invalid");
        }
        try {
            Optional<String> sid = OidcBackChannelSessionSupport.sid(jwt, "Logout Token");
            Optional<String> subject = jwt.subject();
            if (tenant.tenantConfig().logout().orElseThrow().backChannel().orElseThrow().sessionRequired()
                    && sid.isEmpty()) {
                return OidcValidationResult.failure("Logout Token session ID is required");
            }
            return OidcValidationResult.success(new OidcBackChannelLogoutStore.LogoutEvent(
                    tenant.tenantId(), expectedIssuer.orElseThrow(), subject, sid,
                    jwt.jwtId().orElseThrow(), jwt.issueTime().orElseThrow(), jwt.expirationTime().orElseThrow()));
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Logout Token identity is invalid", e);
        }
    }

    private JwtValidator headerValidator(List<String> allowedAlgorithms) {
        return JwtValidator.builder()
                .addCriticalValidator()
                .addValidator(JwtScope.HEADER, (jwt, collector) -> {
                    String algorithm = jwt.algorithm().orElse(null);
                    if (algorithm == null || "none".equalsIgnoreCase(algorithm)
                            || !allowedAlgorithms.contains(algorithm)) {
                        // Back-Channel Logout 2.6 explicitly prohibits alg=none, even if an ID Token profile permits it.
                        collector.fatal(jwt, "Logout Token JWS algorithm is not allowed");
                    }
                    jwt.type()
                            .map(value -> value.toLowerCase(Locale.ROOT))
                            .filter(type -> !ACCEPTED_TYPES.contains(type))
                            .ifPresent(_ -> collector.fatal(jwt, "Logout Token JWS type is not allowed"));
                }, "alg", "typ")
                .build();
    }

    private JwtValidator claimsValidator(OidcIdTokenConfig idToken, String issuer, String clientId, Instant now) {
        return JwtValidator.builder()
                .addExpirationValidator(it -> it.now(now).allowedTimeSkew(idToken.clockSkew()).mandatory(true))
                .addIssueTimeValidator(it -> it.now(now).allowedTimeSkew(idToken.clockSkew()).mandatory(true))
                .addNotBeforeValidator(it -> it.now(now).allowedTimeSkew(idToken.clockSkew()))
                .addIssuerValidator(issuer)
                .addAudienceValidator(clientId)
                .addValidator((jwt, collector) -> idTokenValidator.validateAudience(jwt,
                                                                                    clientId,
                                                                                    idToken.trustedAdditionalAudiences()
                                                                                            .orElseGet(List::of),
                                                                                    collector),
                              "aud", "azp")
                .addValidator(this::validateLogoutClaims, "sub", "sid", "jti", "events", "nonce")
                .build();
    }

    private void validateLogoutClaims(Jwt jwt, Errors.Collector collector) {
        /*
         * Spec: OpenID Connect Back-Channel Logout 1.0, 2.4 and 2.6.
         * https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
         * jti, events, iss/aud/iat/exp are required; either sub or sid is required; nonce is prohibited.
         * Extra claims and nonempty logout event objects are permitted.
         */
        if (jwt.payloadClaimsJson().containsKey("nonce")) {
            collector.fatal(jwt, "Logout Token nonce claim is prohibited");
        }
        if (jwt.payloadClaimValue("jti")
                .filter(value -> value.type() == JsonValueType.STRING)
                .map(value -> value.asString().value())
                .filter(value -> !value.isBlank())
                .isEmpty()) {
            collector.fatal(jwt, "Logout Token jti claim is mandatory");
        }
        Optional<JsonValue> subject = jwt.payloadClaimValue("sub");
        if (subject.isPresent() && subject.filter(value -> value.type() == JsonValueType.STRING)
                .map(value -> value.asString().value())
                .filter(value -> !value.isBlank() && value.length() <= MAX_SUBJECT_LENGTH)
                .filter(value -> value.chars().allMatch(character -> character <= 0x7F))
                .isEmpty()) {
            collector.fatal(jwt, "Logout Token subject claim is invalid");
        }
        Optional<JsonValue> sid = jwt.payloadClaimValue("sid");
        if (sid.isPresent() && sid.filter(value -> value.type() == JsonValueType.STRING)
                .map(value -> value.asString().value())
                .filter(value -> !value.isBlank())
                .isEmpty()) {
            collector.fatal(jwt, "Logout Token sid claim is invalid");
        }
        if (subject.isEmpty() && sid.isEmpty()) {
            collector.fatal(jwt, "Logout Token must contain sub or sid");
        }
        if (jwt.payloadClaimValue("events")
                .filter(value -> value.type() == JsonValueType.OBJECT)
                .flatMap(value -> value.asObject().value(LOGOUT_EVENT))
                .filter(value -> value.type() == JsonValueType.OBJECT)
                .isEmpty()) {
            collector.fatal(jwt, "Logout Token events claim is invalid");
        }
    }
}
