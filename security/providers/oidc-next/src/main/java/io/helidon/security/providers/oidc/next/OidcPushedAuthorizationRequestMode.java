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
 * RFC 9126 Pushed Authorization Request mode.
 */
public enum OidcPushedAuthorizationRequestMode {
    /**
     * Never use Pushed Authorization Requests.
     */
    DISABLED("disabled"),

    /**
     * Use Pushed Authorization Requests when the Authorization Server metadata or static endpoint configuration makes
     * them available, and require them when Authorization Server metadata requires them.
     */
    AUTO("auto"),

    /**
     * Require every Authentication Request to use Pushed Authorization Requests.
     */
    REQUIRED("required");

    private final String text;

    OidcPushedAuthorizationRequestMode(String text) {
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
