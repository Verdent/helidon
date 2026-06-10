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

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Path part of a SPIFFE ID.
 */
public final class SpiffePath {
    private static final SpiffePath ROOT = new SpiffePath("", List.of());

    private final String value;
    private final List<String> segments;

    private SpiffePath(String value, List<String> segments) {
        this.value = value;
        this.segments = List.copyOf(segments);
    }

    /**
     * Create a SPIFFE path.
     *
     * @param value raw path value
     * @return SPIFFE path
     * @throws SpiffeException if the path is invalid
     */
    public static SpiffePath create(String value) {
        Objects.requireNonNull(value, "SPIFFE path must not be null");
        if (value.isEmpty() || "/".equals(value)) {
            return ROOT;
        }
        if (!value.startsWith("/")) {
            throw new SpiffeException("SPIFFE path must start with '/': " + value);
        }
        if (value.endsWith("/")) {
            throw new SpiffeException("SPIFFE path must not end with '/': " + value);
        }
        if (value.indexOf('\\') >= 0 || value.indexOf('?') >= 0 || value.indexOf('#') >= 0) {
            throw new SpiffeException("SPIFFE path contains an invalid character: " + value);
        }

        String[] split = value.substring(1).split("/", -1);
        for (String segment : split) {
            validateSegment(segment, value);
        }
        return new SpiffePath(value, Arrays.asList(split));
    }

    /**
     * Root SPIFFE path.
     *
     * @return root path
     */
    public static SpiffePath root() {
        return ROOT;
    }

    /**
     * Whether this path represents the trust-domain root.
     *
     * @return whether this path is root
     */
    public boolean isRoot() {
        return value.isEmpty();
    }

    /**
     * Raw path value.
     *
     * @return path value, or an empty string for root
     */
    public String value() {
        return value;
    }

    /**
     * Path segments.
     *
     * @return path segments
     */
    public List<String> segments() {
        return segments;
    }

    /**
     * Whether this path starts with a path prefix.
     *
     * @param prefix path prefix
     * @return whether this path starts with the prefix
     */
    public boolean startsWith(SpiffePath prefix) {
        Objects.requireNonNull(prefix, "Path prefix must not be null");
        if (prefix.isRoot()) {
            return true;
        }
        if (segments.size() < prefix.segments.size()) {
            return false;
        }
        for (int i = 0; i < prefix.segments.size(); i++) {
            if (!segments.get(i).equals(prefix.segments.get(i))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SpiffePath that)) {
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
        return value.isEmpty() ? "/" : value;
    }

    private static void validateSegment(String segment, String path) {
        if (segment.isEmpty()) {
            throw new SpiffeException("SPIFFE path must not contain empty segments: " + path);
        }
        if (".".equals(segment) || "..".equals(segment)) {
            throw new SpiffeException("SPIFFE path must not contain '.' or '..' segments: " + path);
        }
        for (int i = 0; i < segment.length(); i++) {
            char ch = segment.charAt(i);
            if (ch <= 0x20 || ch >= 0x7f) {
                throw new SpiffeException("SPIFFE path segment contains a non-printable or non-ASCII character: " + path);
            }
        }
    }
}
