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
 * Proof Key for Code Exchange (PKCE) {@code code_challenge_method}.
 * <p>
 * These values correspond to the {@code code_challenge_method} values defined by RFC 7636,
 * {@code 4.2 Client Creates the Code Challenge}, and registered in the OAuth PKCE Code Challenge Method registry.
 * The {@linkplain #wireName() wire name} is the value sent in the Authorization Request
 * {@code code_challenge_method} parameter.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2">
 * RFC 7636, 4.2 Client Creates the Code Challenge</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html#section-6.2.2">
 * RFC 7636, 6.2.2 PKCE Code Challenge Method Registry</a>
 */
public enum OidcPkceMethod {
    /**
     * {@code plain}.
     * <p>
     * The {@code code_challenge} is the unmodified {@code code_verifier}. This is defined by RFC 7636 for
     * compatibility with Authorization Servers that do not support {@link #S256}.
     */
    PLAIN("plain"),

    /**
     * {@code S256}.
     * <p>
     * The {@code code_challenge} is {@code BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))}. RFC 7636 requires
     * clients to use {@code S256} when they can, and this provider uses it by default.
     */
    S256("S256");

    private final String wireName;

    OidcPkceMethod(String wireName) {
        this.wireName = wireName;
    }

    /**
     * Method name used in the {@code code_challenge_method} authorization request parameter.
     *
     * @return method wire name
     */
    public String wireName() {
        return wireName;
    }
}
