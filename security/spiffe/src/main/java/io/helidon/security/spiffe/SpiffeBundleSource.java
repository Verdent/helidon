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

import java.util.Optional;

/**
 * Source of SPIFFE bundles by trust domain.
 */
@FunctionalInterface
public interface SpiffeBundleSource {
    /**
     * Create a source backed by a fixed bundle set.
     *
     * @param bundleSet bundle set
     * @return bundle source
     */
    static SpiffeBundleSource fixed(SpiffeBundleSet bundleSet) {
        return bundleSet::bundle;
    }

    /**
     * Create a source backed by a single bundle.
     *
     * @param bundle bundle
     * @return bundle source
     */
    static SpiffeBundleSource fixed(SpiffeBundle bundle) {
        return fixed(SpiffeBundleSet.create(bundle));
    }

    /**
     * Get a bundle for a trust domain.
     *
     * @param trustDomain trust domain
     * @return bundle if available
     */
    Optional<SpiffeBundle> bundle(SpiffeTrustDomain trustDomain);
}
