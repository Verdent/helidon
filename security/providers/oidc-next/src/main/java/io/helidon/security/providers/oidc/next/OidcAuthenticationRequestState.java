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
import java.time.Instant;
import java.util.Optional;

final class OidcAuthenticationRequestState {
    private final String tenantId;
    private final String state;
    private final String nonce;
    private final String pkceVerifier;
    private final URI originalUri;
    private final URI redirectionEndpointUri;
    private final Instant createdAt;
    private final Instant expiresAt;

    private OidcAuthenticationRequestState(String tenantId,
                                           String state,
                                           String nonce,
                                           String pkceVerifier,
                                           URI originalUri,
                                           URI redirectionEndpointUri,
                                           Instant createdAt,
                                           Instant expiresAt) {
        this.tenantId = tenantId;
        this.state = state;
        this.nonce = nonce;
        this.pkceVerifier = pkceVerifier;
        this.originalUri = originalUri;
        this.redirectionEndpointUri = redirectionEndpointUri;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    static OidcAuthenticationRequestState create(String tenantId,
                                                 String state,
                                                 String nonce,
                                                 String pkceVerifier,
                                                 URI originalUri,
                                                 URI redirectionEndpointUri,
                                                 Instant createdAt,
                                                 Instant expiresAt) {
        return new OidcAuthenticationRequestState(tenantId,
                                                  state,
                                                  nonce,
                                                  pkceVerifier,
                                                  originalUri,
                                                  redirectionEndpointUri,
                                                  createdAt,
                                                  expiresAt);
    }

    String tenantId() {
        return tenantId;
    }

    String state() {
        return state;
    }

    String nonce() {
        return nonce;
    }

    Optional<String> pkceVerifier() {
        return Optional.ofNullable(pkceVerifier);
    }

    URI originalUri() {
        return originalUri;
    }

    URI redirectionEndpointUri() {
        return redirectionEndpointUri;
    }

    Instant createdAt() {
        return createdAt;
    }

    Instant expiresAt() {
        return expiresAt;
    }
}
