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
 * PKCE code challenge method.
 */
public enum OidcPkceMethod {
    /**
     * Plain code challenge method.
     * <p>
     * This method is intended only for compatibility with authorization servers that do not support S256.
     */
    PLAIN("plain"),

    /**
     * SHA-256 based code challenge method.
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
