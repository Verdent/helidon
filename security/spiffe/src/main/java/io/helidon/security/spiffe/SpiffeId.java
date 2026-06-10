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

import java.net.URI;
import java.util.Objects;

/**
 * SPIFFE ID in URI form.
 */
public final class SpiffeId {
    /**
     * SPIFFE URI scheme.
     */
    public static final String SCHEME = "spiffe";

    private final SpiffeTrustDomain trustDomain;
    private final SpiffePath path;
    private final String value;

    private SpiffeId(SpiffeTrustDomain trustDomain, SpiffePath path) {
        this.trustDomain = trustDomain;
        this.path = path;
        this.value = SCHEME + "://" + trustDomain.value() + path.value();
    }

    /**
     * Create a SPIFFE ID.
     *
     * @param trustDomain trust domain
     * @param path path
     * @return SPIFFE ID
     */
    public static SpiffeId create(SpiffeTrustDomain trustDomain, SpiffePath path) {
        return new SpiffeId(Objects.requireNonNull(trustDomain, "Trust domain must not be null"),
                            Objects.requireNonNull(path, "Path must not be null"));
    }

    /**
     * Parse a SPIFFE ID.
     *
     * @param value SPIFFE ID value
     * @return SPIFFE ID
     * @throws SpiffeException if the value is not a valid SPIFFE ID
     */
    public static SpiffeId parse(String value) {
        Objects.requireNonNull(value, "SPIFFE ID value must not be null");
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw new SpiffeException("SPIFFE ID is not a valid URI: " + value, e);
        }

        if (!SCHEME.equals(uri.getScheme())) {
            throw new SpiffeException("SPIFFE ID must use the spiffe scheme: " + value);
        }
        if (uri.isOpaque()) {
            throw new SpiffeException("SPIFFE ID must be hierarchical: " + value);
        }
        if (uri.getRawUserInfo() != null || uri.getPort() != -1) {
            throw new SpiffeException("SPIFFE ID authority must not contain user info or port: " + value);
        }
        if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new SpiffeException("SPIFFE ID must not contain query or fragment: " + value);
        }

        String authority = uri.getRawAuthority();
        if (authority == null || authority.isEmpty()) {
            throw new SpiffeException("SPIFFE ID must contain a trust domain: " + value);
        }
        if (authority.indexOf('@') >= 0 || authority.indexOf(':') >= 0) {
            throw new SpiffeException("SPIFFE ID authority must contain only a trust domain: " + value);
        }

        String rawPath = uri.getRawPath();
        SpiffeTrustDomain trustDomain = SpiffeTrustDomain.create(authority);
        SpiffePath path = SpiffePath.create(rawPath == null ? "" : rawPath);
        return create(trustDomain, path);
    }

    /**
     * Trust domain.
     *
     * @return trust domain
     */
    public SpiffeTrustDomain trustDomain() {
        return trustDomain;
    }

    /**
     * Path.
     *
     * @return path
     */
    public SpiffePath path() {
        return path;
    }

    /**
     * Whether this ID is the trust-domain root ID.
     *
     * @return whether this ID is root
     */
    public boolean isRoot() {
        return path.isRoot();
    }

    /**
     * SPIFFE ID URI value.
     *
     * @return SPIFFE ID value
     */
    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SpiffeId spiffeId)) {
            return false;
        }
        return value.equals(spiffeId.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return value;
    }
}
