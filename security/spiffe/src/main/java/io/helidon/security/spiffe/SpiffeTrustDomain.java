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
 * SPIFFE trust domain.
 */
public final class SpiffeTrustDomain implements Comparable<SpiffeTrustDomain> {
    private final String value;

    private SpiffeTrustDomain(String value) {
        this.value = value;
    }

    /**
     * Create a trust domain from its textual representation.
     *
     * @param value trust domain value
     * @return trust domain
     * @throws SpiffeException if the value is not a valid SPIFFE trust domain
     */
    public static SpiffeTrustDomain create(String value) {
        Objects.requireNonNull(value, "Trust domain value must not be null");
        if (value.isEmpty()) {
            throw new SpiffeException("SPIFFE trust domain must not be empty");
        }
        String[] labels = value.split("\\.", -1);
        for (String label : labels) {
            validateLabel(label, value);
        }

        return new SpiffeTrustDomain(value);
    }

    /**
     * Trust domain value.
     *
     * @return trust domain value
     */
    public String value() {
        return value;
    }

    @Override
    public int compareTo(SpiffeTrustDomain other) {
        return value.compareTo(other.value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SpiffeTrustDomain that)) {
            return false;
        }
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return value;
    }

    private static void validateLabel(String label, String trustDomain) {
        if (label.isEmpty()) {
            throw new SpiffeException("SPIFFE trust domain must not contain empty labels: " + trustDomain);
        }
        if (label.startsWith("-") || label.endsWith("-")) {
            throw new SpiffeException("SPIFFE trust domain labels must not start or end with '-': " + trustDomain);
        }
        for (int i = 0; i < label.length(); i++) {
            char ch = label.charAt(i);
            if ((ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '-') {
                continue;
            }
            throw new SpiffeException("SPIFFE trust domain contains an invalid character: " + trustDomain);
        }
    }
}
