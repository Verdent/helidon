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

/**
 * RFC 8705 certificate-bound access-token validation mode.
 */
public enum OidcCertificateBoundAccessTokenMode {
    /**
     * Reject certificate-bound access tokens on Bearer Token validation paths.
     */
    DISABLED("disabled"),

    /**
     * Validate certificate binding when the access token contains {@code cnf.x5t#S256}.
     */
    IF_PRESENT("if-present"),

    /**
     * Require every protected-resource Bearer Token access token to contain {@code cnf.x5t#S256} and match the
     * request TLS client certificate.
     */
    REQUIRED("required");

    private final String text;

    OidcCertificateBoundAccessTokenMode(String text) {
        this.text = text;
    }

    /**
     * Config text value.
     *
     * @return config text value
     */
    public String text() {
        return text;
    }
}
