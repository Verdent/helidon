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
import java.util.Optional;

final class OidcEndpointClient {
    private final String tenantId;
    private final OidcProviderMetadata metadata;

    private OidcEndpointClient(String tenantId, OidcProviderMetadata metadata) {
        this.tenantId = tenantId;
        this.metadata = metadata;
    }

    static OidcEndpointClient create(String tenantId, OidcProviderMetadata metadata) {
        return new OidcEndpointClient(tenantId, metadata);
    }

    String tenantId() {
        return tenantId;
    }

    Optional<URI> authorizationEndpointUri() {
        return metadata.authorizationEndpointUri();
    }

    Optional<URI> tokenEndpointUri() {
        return metadata.tokenEndpointUri();
    }

    Optional<URI> introspectionEndpointUri() {
        return metadata.introspectionEndpointUri();
    }

    Optional<URI> userInfoEndpointUri() {
        return metadata.userInfoEndpointUri();
    }

    Optional<URI> endSessionEndpointUri() {
        return metadata.endSessionEndpointUri();
    }
}
