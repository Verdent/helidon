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

package io.helidon.security.spiffe;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import io.helidon.common.Errors;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkEC;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;

/**
 * Validator for SPIFFE JWT-SVIDs.
 */
public final class JwtSvidValidator {
    private static final Set<String> DEFAULT_ALLOWED_ALGORITHMS = Set.of(JwkRSA.ALG_RS256,
                                                                         JwkRSA.ALG_RS384,
                                                                         JwkRSA.ALG_RS512,
                                                                         JwkEC.ALG_ES256,
                                                                         JwkEC.ALG_ES384,
                                                                         JwkEC.ALG_ES512);

    private final SpiffeBundleSource bundleSource;
    private final List<String> expectedAudiences;
    private final Set<String> allowedAlgorithms;
    private final List<SpiffeIdMatcher> subjectMatchers;
    private final Duration clockSkew;
    private final Clock clock;

    private JwtSvidValidator(Builder builder) {
        if (builder.expectedAudiences.isEmpty()) {
            throw new SpiffeException("JWT-SVID validator must have at least one expected audience");
        }
        this.bundleSource = Objects.requireNonNull(builder.bundleSource, "Bundle source must not be null");
        this.expectedAudiences = List.copyOf(builder.expectedAudiences);
        this.allowedAlgorithms = Set.copyOf(builder.allowedAlgorithms);
        this.subjectMatchers = List.copyOf(builder.subjectMatchers);
        this.clockSkew = builder.clockSkew;
        this.clock = builder.clock;
    }

    /**
     * Create a builder.
     *
     * @return builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Validate a JWT-SVID token.
     *
     * @param tokenContent serialized token
     * @return validation result
     */
    public SpiffeValidationResult<JwtSvid> validate(String tokenContent) {
        JwtSvid svid;
        try {
            svid = JwtSvid.parse(tokenContent);
        } catch (RuntimeException e) {
            return SpiffeValidationResult.failure("JWT-SVID parsing failed", e);
        }

        String algorithm = svid.jwt().algorithm().orElse(null);
        if (algorithm == null) {
            return SpiffeValidationResult.failure("JWT-SVID must contain a JOSE alg header");
        }
        if (Jwk.ALG_NONE.equals(algorithm)) {
            return SpiffeValidationResult.failure("JWT-SVID must not use the none algorithm");
        }
        if (!allowedAlgorithms.contains(algorithm)) {
            return SpiffeValidationResult.failure("JWT-SVID uses an unsupported algorithm: " + algorithm);
        }
        if (!hasExpectedAudience(svid)) {
            return SpiffeValidationResult.failure("JWT-SVID does not contain an expected audience");
        }
        SpiffeValidationResult<JwtSvid> timeResult = validateTime(svid);
        if (!timeResult.isValid()) {
            return timeResult;
        }
        if (!matchesSubject(svid.spiffeId())) {
            return SpiffeValidationResult.failure("JWT-SVID subject is not accepted: " + svid.spiffeId());
        }

        SpiffeBundle bundle = bundleSource.bundle(svid.spiffeId().trustDomain())
                .orElse(null);
        if (bundle == null) {
            return SpiffeValidationResult.failure("No SPIFFE bundle found for trust domain: "
                                                          + svid.spiffeId().trustDomain());
        }
        if (!bundle.hasJwtSvidKeys()) {
            return SpiffeValidationResult.failure("SPIFFE bundle has no JWT-SVID keys for trust domain: "
                                                          + bundle.trustDomain());
        }

        JwkKeys jwtSvidKeys = bundle.jwtSvidKeys();
        Jwk defaultJwk = defaultJwk(svid, jwtSvidKeys);
        Errors signatureErrors = svid.signedJwt().verifySignature(jwtSvidKeys, defaultJwk);
        if (!signatureErrors.isValid()) {
            return SpiffeValidationResult.failure("JWT-SVID signature is invalid: " + signatureErrors);
        }

        return SpiffeValidationResult.success(svid);
    }

    private boolean hasExpectedAudience(JwtSvid svid) {
        for (String audience : svid.audiences()) {
            if (expectedAudiences.contains(audience)) {
                return true;
            }
        }
        return false;
    }

    private SpiffeValidationResult<JwtSvid> validateTime(JwtSvid svid) {
        Instant now = clock.instant();
        if (!now.minus(clockSkew).isBefore(svid.expiresAt())) {
            return SpiffeValidationResult.failure("JWT-SVID is expired");
        }
        if (svid.notBefore().filter(notBefore -> now.plus(clockSkew).isBefore(notBefore)).isPresent()) {
            return SpiffeValidationResult.failure("JWT-SVID is not yet valid");
        }
        if (svid.issuedAt().filter(issuedAt -> now.plus(clockSkew).isBefore(issuedAt)).isPresent()) {
            return SpiffeValidationResult.failure("JWT-SVID was issued in the future");
        }
        return SpiffeValidationResult.success(svid);
    }

    private boolean matchesSubject(SpiffeId spiffeId) {
        if (subjectMatchers.isEmpty()) {
            return true;
        }
        for (SpiffeIdMatcher subjectMatcher : subjectMatchers) {
            if (subjectMatcher.matches(spiffeId)) {
                return true;
            }
        }
        return false;
    }

    private static Jwk defaultJwk(JwtSvid svid, JwkKeys jwtSvidKeys) {
        if (svid.jwt().keyId().isPresent()) {
            return null;
        }
        List<Jwk> keys = jwtSvidKeys.keys();
        if (keys.size() == 1) {
            return keys.get(0);
        }
        return null;
    }

    /**
     * Builder for {@link JwtSvidValidator}.
     */
    public static final class Builder implements io.helidon.common.Builder<Builder, JwtSvidValidator> {
        private SpiffeBundleSource bundleSource;
        private List<String> expectedAudiences = new LinkedList<>();
        private Set<String> allowedAlgorithms = new LinkedHashSet<>(DEFAULT_ALLOWED_ALGORITHMS);
        private List<SpiffeIdMatcher> subjectMatchers = new LinkedList<>();
        private Duration clockSkew = Duration.ZERO;
        private Clock clock = Clock.systemUTC();

        private Builder() {
        }

        @Override
        public JwtSvidValidator build() {
            return new JwtSvidValidator(this);
        }

        /**
         * Configure the source of trust bundles.
         *
         * @param bundleSource bundle source
         * @return updated builder
         */
        public Builder bundleSource(SpiffeBundleSource bundleSource) {
            this.bundleSource = Objects.requireNonNull(bundleSource, "Bundle source must not be null");
            return this;
        }

        /**
         * Add an expected audience.
         *
         * @param audience expected audience
         * @return updated builder
         */
        public Builder addAudience(String audience) {
            expectedAudiences.add(Objects.requireNonNull(audience, "Audience must not be null"));
            return this;
        }

        /**
         * Replace expected audiences.
         *
         * @param audiences expected audiences
         * @return updated builder
         */
        public Builder audiences(List<String> audiences) {
            this.expectedAudiences = new LinkedList<>(audiences);
            return this;
        }

        /**
         * Replace allowed JOSE algorithms.
         *
         * @param algorithms allowed algorithms
         * @return updated builder
         */
        public Builder allowedAlgorithms(Set<String> algorithms) {
            this.allowedAlgorithms = new LinkedHashSet<>(algorithms);
            return this;
        }

        /**
         * Add a matcher for accepted SPIFFE subjects.
         *
         * @param matcher subject matcher
         * @return updated builder
         */
        public Builder addSubjectMatcher(SpiffeIdMatcher matcher) {
            this.subjectMatchers.add(Objects.requireNonNull(matcher, "Subject matcher must not be null"));
            return this;
        }

        /**
         * Configure clock skew allowance.
         *
         * @param clockSkew clock skew allowance
         * @return updated builder
         */
        public Builder clockSkew(Duration clockSkew) {
            this.clockSkew = Objects.requireNonNull(clockSkew, "Clock skew must not be null");
            return this;
        }

        /**
         * Configure validation clock.
         *
         * @param clock validation clock
         * @return updated builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "Clock must not be null");
            return this;
        }
    }
}
