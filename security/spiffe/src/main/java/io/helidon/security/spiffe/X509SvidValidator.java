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

import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Validator for SPIFFE X.509-SVIDs.
 */
public final class X509SvidValidator {
    private final SpiffeBundleSource bundleSource;
    private final List<SpiffeIdMatcher> subjectMatchers;
    private final Duration clockSkew;
    private final Clock clock;

    private X509SvidValidator(Builder builder) {
        this.bundleSource = Objects.requireNonNull(builder.bundleSource, "Bundle source must not be null");
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
     * Validate an X.509-SVID certificate chain.
     *
     * @param certificateChain certificate chain with the leaf certificate first
     * @return validation result
     */
    public SpiffeValidationResult<X509Svid> validate(List<X509Certificate> certificateChain) {
        X509Svid svid;
        try {
            svid = X509Svid.create(certificateChain);
        } catch (RuntimeException e) {
            return SpiffeValidationResult.failure("X.509-SVID parsing failed", e);
        }

        SpiffeValidationResult<X509Svid> timeResult = validateTime(svid);
        if (!timeResult.isValid()) {
            return timeResult;
        }
        if (!matchesSubject(svid.spiffeId())) {
            return SpiffeValidationResult.failure("X.509-SVID subject is not accepted: " + svid.spiffeId());
        }

        SpiffeBundle bundle = bundleSource.bundle(svid.spiffeId().trustDomain())
                .orElse(null);
        if (bundle == null) {
            return SpiffeValidationResult.failure("No SPIFFE bundle found for trust domain: "
                                                          + svid.spiffeId().trustDomain());
        }
        if (!bundle.hasX509Authorities()) {
            return SpiffeValidationResult.failure("SPIFFE bundle has no X.509 authorities for trust domain: "
                                                          + bundle.trustDomain());
        }

        try {
            validateCertificationPath(svid, bundle);
        } catch (Exception e) {
            return SpiffeValidationResult.failure("X.509-SVID certificate path is invalid", e);
        }

        return SpiffeValidationResult.success(svid);
    }

    private SpiffeValidationResult<X509Svid> validateTime(X509Svid svid) {
        Instant now = clock.instant();
        if (!now.minus(clockSkew).isBefore(svid.expiresAt())) {
            return SpiffeValidationResult.failure("X.509-SVID is expired");
        }
        if (svid.notBefore().filter(notBefore -> now.plus(clockSkew).isBefore(notBefore)).isPresent()) {
            return SpiffeValidationResult.failure("X.509-SVID is not yet valid");
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

    private void validateCertificationPath(X509Svid svid, SpiffeBundle bundle) throws Exception {
        List<X509Certificate> chain = certificateChainWithoutTrustAnchor(svid.certificateChain(), bundle.x509Authorities());
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        CertPath certPath = certificateFactory.generateCertPath(chain);

        Set<TrustAnchor> trustAnchors = new LinkedHashSet<>();
        for (X509Certificate certificate : bundle.x509Authorities()) {
            trustAnchors.add(new TrustAnchor(certificate, null));
        }

        PKIXParameters parameters = new PKIXParameters(trustAnchors);
        parameters.setRevocationEnabled(false);
        parameters.setDate(Date.from(clock.instant()));

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(certPath, parameters);
    }

    private static List<X509Certificate> certificateChainWithoutTrustAnchor(List<X509Certificate> chain,
                                                                           List<X509Certificate> authorities) {
        if (chain.size() <= 1) {
            return chain;
        }
        X509Certificate last = chain.get(chain.size() - 1);
        if (authorities.contains(last)) {
            return List.copyOf(chain.subList(0, chain.size() - 1));
        }
        return chain;
    }

    /**
     * Builder for {@link X509SvidValidator}.
     */
    public static final class Builder implements io.helidon.common.Builder<Builder, X509SvidValidator> {
        private SpiffeBundleSource bundleSource;
        private List<SpiffeIdMatcher> subjectMatchers = new LinkedList<>();
        private Duration clockSkew = Duration.ZERO;
        private Clock clock = Clock.systemUTC();

        private Builder() {
        }

        @Override
        public X509SvidValidator build() {
            return new X509SvidValidator(this);
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
