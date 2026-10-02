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
 * JWT access-token layout validated by a Protected Resource or during token refresh.
 */
public enum OidcJwtAccessTokenProfile {
    /**
     * RFC 9068 JWT Access Token Profile, including its required token type and claims.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9068.html">RFC 9068</a>
     */
    RFC_9068,

    /**
     * Explicit provider-specific token types, required claims, and required string claim values.
     * Signature, issuer, and expiration validation remain required. Audience validation is enabled by default and
     * can be disabled explicitly for this profile.
     */
    CUSTOM
}
