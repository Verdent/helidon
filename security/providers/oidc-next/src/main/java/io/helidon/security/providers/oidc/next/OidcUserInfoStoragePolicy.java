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
 * UserInfo claim storage policy for Authorization Code Flow local authentication.
 */
public enum OidcUserInfoStoragePolicy {
    /**
     * Store only UserInfo claims needed by subject mapping, plus explicitly configured attribute claim paths.
     */
    MAPPED("mapped"),

    /**
     * Store the complete UserInfo JSON object.
     */
    ALL("all"),

    /**
     * Validate the UserInfo response, then discard it.
     */
    NONE("none");

    private final String text;

    OidcUserInfoStoragePolicy(String text) {
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
