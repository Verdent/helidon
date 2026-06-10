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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Set of SPIFFE trust bundles keyed by trust domain.
 */
public final class SpiffeBundleSet implements SpiffeBundleSource {
    private final Map<SpiffeTrustDomain, SpiffeBundle> bundles;

    private SpiffeBundleSet(Builder builder) {
        this.bundles = Map.copyOf(builder.bundles);
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
     * Create a bundle set with a single bundle.
     *
     * @param bundle bundle
     * @return bundle set
     */
    public static SpiffeBundleSet create(SpiffeBundle bundle) {
        return builder().addBundle(bundle).build();
    }

    @Override
    public Optional<SpiffeBundle> bundle(SpiffeTrustDomain trustDomain) {
        return Optional.ofNullable(bundles.get(trustDomain));
    }

    /**
     * Bundles in this set.
     *
     * @return bundles
     */
    public Collection<SpiffeBundle> bundles() {
        return bundles.values();
    }

    /**
     * Builder for {@link SpiffeBundleSet}.
     */
    public static final class Builder implements io.helidon.common.Builder<Builder, SpiffeBundleSet> {
        private final Map<SpiffeTrustDomain, SpiffeBundle> bundles = new LinkedHashMap<>();

        private Builder() {
        }

        @Override
        public SpiffeBundleSet build() {
            return new SpiffeBundleSet(this);
        }

        /**
         * Add a bundle.
         *
         * @param bundle bundle
         * @return updated builder
         */
        public Builder addBundle(SpiffeBundle bundle) {
            Objects.requireNonNull(bundle, "Bundle must not be null");
            bundles.put(bundle.trustDomain(), bundle);
            return this;
        }
    }
}
