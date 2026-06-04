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
 * Credential types accepted by an OIDC endpoint policy.
 */
public enum OidcEndpointCredential {
    /**
     * OAuth 2.0 Bearer Token credential accepted by Protected Resource authentication.
     */
    BEARER_TOKEN("bearer-token"),

    /**
     * Local authentication cookie created by Authorization Code Flow.
     */
    AUTHENTICATION_COOKIE("authentication-cookie");

    private final String configValue;

    OidcEndpointCredential(String configValue) {
        this.configValue = configValue;
    }

    @Override
    public String toString() {
        return configValue;
    }
}
