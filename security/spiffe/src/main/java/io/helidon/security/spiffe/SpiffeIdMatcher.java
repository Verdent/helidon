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

import java.util.Objects;

/**
 * Matcher for accepted SPIFFE IDs.
 */
@FunctionalInterface
public interface SpiffeIdMatcher {
    /**
     * Match any SPIFFE ID.
     *
     * @return matcher
     */
    static SpiffeIdMatcher any() {
        return id -> true;
    }

    /**
     * Match an exact SPIFFE ID.
     *
     * @param expected expected SPIFFE ID
     * @return matcher
     */
    static SpiffeIdMatcher exact(SpiffeId expected) {
        Objects.requireNonNull(expected, "Expected SPIFFE ID must not be null");
        return expected::equals;
    }

    /**
     * Match IDs in a trust domain.
     *
     * @param trustDomain expected trust domain
     * @return matcher
     */
    static SpiffeIdMatcher trustDomain(SpiffeTrustDomain trustDomain) {
        Objects.requireNonNull(trustDomain, "Trust domain must not be null");
        return id -> trustDomain.equals(id.trustDomain());
    }

    /**
     * Match IDs in the same trust domain that start with a path prefix.
     *
     * @param prefix prefix ID
     * @return matcher
     */
    static SpiffeIdMatcher startsWith(SpiffeId prefix) {
        Objects.requireNonNull(prefix, "SPIFFE ID prefix must not be null");
        return id -> prefix.trustDomain().equals(id.trustDomain()) && id.path().startsWith(prefix.path());
    }

    /**
     * Whether the SPIFFE ID matches.
     *
     * @param spiffeId SPIFFE ID
     * @return whether the ID matches
     */
    boolean matches(SpiffeId spiffeId);

    /**
     * Combine this matcher with another matcher using logical and.
     *
     * @param other other matcher
     * @return combined matcher
     */
    default SpiffeIdMatcher and(SpiffeIdMatcher other) {
        Objects.requireNonNull(other, "Other matcher must not be null");
        return id -> matches(id) && other.matches(id);
    }

    /**
     * Combine this matcher with another matcher using logical or.
     *
     * @param other other matcher
     * @return combined matcher
     */
    default SpiffeIdMatcher or(SpiffeIdMatcher other) {
        Objects.requireNonNull(other, "Other matcher must not be null");
        return id -> matches(id) || other.matches(id);
    }
}
