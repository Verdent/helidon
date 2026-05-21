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

final class OidcProviderMetadata {
    private final Optional<URI> issuer;
    private final Optional<URI> discoveryUri;
    private final Optional<URI> authorizationEndpointUri;
    private final Optional<URI> tokenEndpointUri;
    private final Optional<URI> jwkSetUri;
    private final Optional<URI> introspectionEndpointUri;
    private final Optional<URI> userInfoEndpointUri;
    private final Optional<URI> endSessionEndpointUri;

    private OidcProviderMetadata(Optional<URI> issuer,
                                 Optional<URI> discoveryUri,
                                 Optional<URI> authorizationEndpointUri,
                                 Optional<URI> tokenEndpointUri,
                                 Optional<URI> jwkSetUri,
                                 Optional<URI> introspectionEndpointUri,
                                 Optional<URI> userInfoEndpointUri,
                                 Optional<URI> endSessionEndpointUri) {
        this.issuer = issuer;
        this.discoveryUri = discoveryUri;
        this.authorizationEndpointUri = authorizationEndpointUri;
        this.tokenEndpointUri = tokenEndpointUri;
        this.jwkSetUri = jwkSetUri;
        this.introspectionEndpointUri = introspectionEndpointUri;
        this.userInfoEndpointUri = userInfoEndpointUri;
        this.endSessionEndpointUri = endSessionEndpointUri;
    }

    static OidcProviderMetadata fromStaticConfig(OidcTenantConfig tenantConfig) {
        OidcEndpointConfig endpoints = tenantConfig.endpoints();
        return create(tenantConfig.issuer(),
                      endpoints.discoveryUri(),
                      endpoints.authorizationEndpointUri(),
                      endpoints.tokenEndpointUri(),
                      endpoints.jwksUri(),
                      endpoints.introspectionEndpointUri(),
                      endpoints.userInfoEndpointUri(),
                      endpoints.endSessionEndpointUri());
    }

    static OidcProviderMetadata create(Optional<URI> issuer,
                                       Optional<URI> discoveryUri,
                                       Optional<URI> authorizationEndpointUri,
                                       Optional<URI> tokenEndpointUri,
                                       Optional<URI> jwkSetUri,
                                       Optional<URI> introspectionEndpointUri,
                                       Optional<URI> userInfoEndpointUri,
                                       Optional<URI> endSessionEndpointUri) {
        return new OidcProviderMetadata(issuer,
                                        discoveryUri,
                                        authorizationEndpointUri,
                                        tokenEndpointUri,
                                        jwkSetUri,
                                        introspectionEndpointUri,
                                        userInfoEndpointUri,
                                        endSessionEndpointUri);
    }

    OidcProviderMetadata mergeDiscovered(OidcProviderMetadata discoveredMetadata) {
        validateDiscoveredIssuer(discoveredMetadata);
        return create(issuer.or(discoveredMetadata::issuer),
                      discoveryUri.or(discoveredMetadata::discoveryUri),
                      authorizationEndpointUri.or(discoveredMetadata::authorizationEndpointUri),
                      tokenEndpointUri.or(discoveredMetadata::tokenEndpointUri),
                      jwkSetUri.or(discoveredMetadata::jwkSetUri),
                      introspectionEndpointUri.or(discoveredMetadata::introspectionEndpointUri),
                      userInfoEndpointUri.or(discoveredMetadata::userInfoEndpointUri),
                      endSessionEndpointUri.or(discoveredMetadata::endSessionEndpointUri));
    }

    Optional<URI> issuer() {
        return issuer;
    }

    Optional<URI> discoveryUri() {
        return discoveryUri;
    }

    Optional<URI> authorizationEndpointUri() {
        return authorizationEndpointUri;
    }

    Optional<URI> tokenEndpointUri() {
        return tokenEndpointUri;
    }

    Optional<URI> jwkSetUri() {
        return jwkSetUri;
    }

    Optional<URI> introspectionEndpointUri() {
        return introspectionEndpointUri;
    }

    Optional<URI> userInfoEndpointUri() {
        return userInfoEndpointUri;
    }

    Optional<URI> endSessionEndpointUri() {
        return endSessionEndpointUri;
    }

    private void validateDiscoveredIssuer(OidcProviderMetadata discoveredMetadata) {
        URI discoveredIssuer = discoveredMetadata.issuer()
                .orElseThrow(() -> new IllegalArgumentException("discovered issuer must be present"));
        if (issuer.isEmpty()) {
            return;
        }
        if (!issuer.get().equals(discoveredIssuer)) {
            throw new IllegalArgumentException("discovered issuer must match configured issuer");
        }
    }
}
