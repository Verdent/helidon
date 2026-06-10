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

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import io.helidon.security.jwt.jwk.JwkKeys;

/**
 * SPIFFE trust bundle for a trust domain.
 */
public final class SpiffeBundle {
    private final SpiffeTrustDomain trustDomain;
    private final JwkKeys jwtSvidKeys;
    private final List<X509Certificate> x509Authorities;

    private SpiffeBundle(Builder builder) {
        this.trustDomain = Objects.requireNonNull(builder.trustDomain, "Trust domain must not be null");
        this.jwtSvidKeys = builder.jwtSvidKeys;
        this.x509Authorities = List.copyOf(builder.x509Authorities);
    }

    /**
     * Create a builder.
     *
     * @param trustDomain trust domain
     * @return builder
     */
    public static Builder builder(SpiffeTrustDomain trustDomain) {
        return new Builder(trustDomain);
    }

    /**
     * Trust domain this bundle belongs to.
     *
     * @return trust domain
     */
    public SpiffeTrustDomain trustDomain() {
        return trustDomain;
    }

    /**
     * JWK keys that can verify JWT-SVIDs.
     *
     * @return JWT-SVID keys
     */
    public JwkKeys jwtSvidKeys() {
        return jwtSvidKeys;
    }

    /**
     * Whether the bundle contains any JWT-SVID keys.
     *
     * @return whether JWT-SVID keys are present
     */
    public boolean hasJwtSvidKeys() {
        return !jwtSvidKeys.keys().isEmpty();
    }

    /**
     * X.509 trust anchors that can verify X.509-SVID chains.
     *
     * @return X.509 trust anchors
     */
    public List<X509Certificate> x509Authorities() {
        return x509Authorities;
    }

    /**
     * Whether the bundle contains any X.509 trust anchors.
     *
     * @return whether X.509 trust anchors are present
     */
    public boolean hasX509Authorities() {
        return !x509Authorities.isEmpty();
    }

    /**
     * Builder for {@link SpiffeBundle}.
     */
    public static final class Builder implements io.helidon.common.Builder<Builder, SpiffeBundle> {
        private final SpiffeTrustDomain trustDomain;
        private JwkKeys jwtSvidKeys = JwkKeys.builder().build();
        private List<X509Certificate> x509Authorities = List.of();

        private Builder(SpiffeTrustDomain trustDomain) {
            this.trustDomain = Objects.requireNonNull(trustDomain, "Trust domain must not be null");
        }

        @Override
        public SpiffeBundle build() {
            return new SpiffeBundle(this);
        }

        /**
         * Configure JWT-SVID verification keys.
         *
         * @param jwtSvidKeys JWT-SVID keys
         * @return updated builder
         */
        public Builder jwtSvidKeys(JwkKeys jwtSvidKeys) {
            this.jwtSvidKeys = Objects.requireNonNull(jwtSvidKeys, "JWT-SVID keys must not be null");
            return this;
        }

        /**
         * Configure X.509 authorities.
         *
         * @param x509Authorities X.509 authorities
         * @return updated builder
         */
        public Builder x509Authorities(List<X509Certificate> x509Authorities) {
            this.x509Authorities = List.copyOf(x509Authorities);
            return this;
        }
    }
}
