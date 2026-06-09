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

import java.util.EnumSet;
import java.util.Set;

final class OidcEndpointPolicy {
    private final Set<OidcEndpointCredential> acceptedCredentials;
    private final OidcAuthenticationFailureResponse authenticationFailureResponse;

    private OidcEndpointPolicy(Set<OidcEndpointCredential> acceptedCredentials,
                               OidcAuthenticationFailureResponse authenticationFailureResponse) {
        this.acceptedCredentials = Set.copyOf(acceptedCredentials);
        this.authenticationFailureResponse = authenticationFailureResponse;
    }

    static OidcEndpointPolicy create(Set<OidcEndpointCredential> acceptedCredentials,
                                     OidcAuthenticationFailureResponse authenticationFailureResponse) {
        return new OidcEndpointPolicy(acceptedCredentials, authenticationFailureResponse);
    }

    static OidcEndpointPolicy protectedResource() {
        return new OidcEndpointPolicy(EnumSet.of(OidcEndpointCredential.BEARER_TOKEN),
                                      OidcAuthenticationFailureResponse.UNAUTHORIZED);
    }

    static OidcEndpointPolicy protectedResourceAndAuthorizationCodeFlow() {
        return new OidcEndpointPolicy(EnumSet.of(OidcEndpointCredential.BEARER_TOKEN,
                                                 OidcEndpointCredential.AUTHENTICATION_COOKIE),
                                      OidcAuthenticationFailureResponse.UNAUTHORIZED);
    }

    boolean bearerTokenAuthenticationEnabled() {
        return acceptedCredentials.contains(OidcEndpointCredential.BEARER_TOKEN);
    }

    boolean authenticationCookieAccepted() {
        return acceptedCredentials.contains(OidcEndpointCredential.AUTHENTICATION_COOKIE);
    }

    OidcAuthenticationFailureResponse authenticationFailureResponse() {
        return authenticationFailureResponse;
    }
}
