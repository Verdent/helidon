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

import java.net.URI;

final class OidcAuthenticationRequest {
    private final URI authorizationUri;
    private final String stateCookie;

    private OidcAuthenticationRequest(URI authorizationUri, String stateCookie) {
        this.authorizationUri = authorizationUri;
        this.stateCookie = stateCookie;
    }

    static OidcAuthenticationRequest create(URI authorizationUri, String stateCookie) {
        return new OidcAuthenticationRequest(authorizationUri, stateCookie);
    }

    URI authorizationUri() {
        return authorizationUri;
    }

    String stateCookie() {
        return stateCookie;
    }
}
