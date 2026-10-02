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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Resolves the Authorization Response issuer-identification policy required to prevent authorization-server mix-up.
 */
final class OidcMixUpProtection {
    private OidcMixUpProtection() {
    }

    static void validateIssuerBindings(Map<String, OidcTenantConfig> configuredTenants,
                                       boolean issuerUniquenessValidationEnabled) {
        List<AuthorizationCodeTenant> tenants = authorizationCodeTenants(configuredTenants);
        for (int firstIndex = 0; firstIndex < tenants.size(); firstIndex++) {
            AuthorizationCodeTenant first = tenants.get(firstIndex);
            for (int secondIndex = firstIndex + 1; secondIndex < tenants.size(); secondIndex++) {
                AuthorizationCodeTenant second = tenants.get(secondIndex);
                if (mayShareIssuer(first, second)
                        && differentEndpoints(first, second)) {
                    /*
                     * Spec: RFC 9207, 4 Security Considerations
                     * https://www.rfc-editor.org/rfc/rfc9207.html#section-4
                     * The same accepted issuer cannot identify independently configured authorization servers.
                     */
                    if (issuerUniquenessValidationEnabled) {
                        throw new IllegalArgumentException("OIDC tenants that may share an issuer must use matching "
                                                                   + "authorization-endpoint-uri and token-endpoint-uri "
                                                                   + "settings");
                    }
                    // With a colliding issuer, the response iss cannot distinguish these ASs. RFC 9700 section
                    // 4.4.2.2 describes distinct redirect URIs as an alternative mix-up defense. Bind the expected
                    // callback and each endpoint to the selected tenant before sending a code or its PKCE verifier.
                    if (first.issuer().isEmpty() || !first.issuer().equals(second.issuer())
                            || first.endpoints().authorizationEndpointUri().isEmpty()
                            || second.endpoints().authorizationEndpointUri().isEmpty()
                            || first.endpoints().tokenEndpointUri().isEmpty()
                            || second.endpoints().tokenEndpointUri().isEmpty()) {
                        throw new IllegalArgumentException("Shared-issuer compatibility requires explicit matching "
                                                                   + "issuer and authorization/token endpoints for each tenant");
                    }
                    if (OidcUri.sameOrigin(first.endpoints().authorizationEndpointUri().orElseThrow(),
                                           second.endpoints().authorizationEndpointUri().orElseThrow())
                            && !first.endpoints().tokenEndpointUri().equals(second.endpoints().tokenEndpointUri())) {
                        // A tenant claiming another AS's authorization endpoint but using a different Token Endpoint
                        // can trick a client into revealing an honest code and its PKCE verifier before ID Token checks.
                        throw new IllegalArgumentException("Shared-issuer compatibility must not associate one "
                                                                   + "Authorization Endpoint origin with different "
                                                                   + "token-endpoint-uri settings");
                    }
                    if (redirectionEndpointsMayOverlap(first, second)) {
                        throw new IllegalArgumentException("Shared-issuer compatibility requires distinct "
                                                                   + "redirection-endpoint-uri paths or origins");
                    }
                }
            }
        }
    }

    /**
     * Returns tenants that must receive the RFC 9207 {@code iss} Authorization Response parameter.
     * <p>
     * RFC 9700 permits a client interacting with multiple authorization servers to use distinct redirection URIs as its
     * mix-up defense. When redirection endpoints can overlap, issuer identification is mandatory instead. A tenant with
     * no statically configured issuer is conservatively treated as a distinct authorization server; users can configure
     * the common issuer explicitly when multiple tenant definitions intentionally address the same server.
     *
     * @param config provider configuration
     * @return immutable set of tenant ids that require issuer identification
     */
    static Set<String> issuerParameterRequiredTenants(OidcProviderConfig config) {
        List<AuthorizationCodeTenant> tenants = authorizationCodeTenants(config.tenants());
        Set<String> required = new LinkedHashSet<>();
        for (int firstIndex = 0; firstIndex < tenants.size(); firstIndex++) {
            AuthorizationCodeTenant first = tenants.get(firstIndex);
            for (int secondIndex = firstIndex + 1; secondIndex < tenants.size(); secondIndex++) {
                AuthorizationCodeTenant second = tenants.get(secondIndex);
                if (differentAuthorizationServers(first, second) && redirectionEndpointsMayOverlap(first, second)) {
                    required.add(first.tenantId());
                    required.add(second.tenantId());
                }
            }
        }
        return Set.copyOf(required);
    }

    private static List<AuthorizationCodeTenant> authorizationCodeTenants(Map<String, OidcTenantConfig> configuredTenants) {
        return configuredTenants.entrySet()
                .stream()
                .filter(entry -> entry.getValue().enabled())
                .map(OidcMixUpProtection::authorizationCodeTenant)
                .flatMap(Optional::stream)
                .toList();
    }

    private static Optional<AuthorizationCodeTenant> authorizationCodeTenant(Map.Entry<String, OidcTenantConfig> entry) {
        OidcTenantConfig tenant = entry.getValue();
        return tenant.authorizationCode()
                .filter(OidcAuthorizationCodeConfig::enabled)
                .map(authorizationCode -> new AuthorizationCodeTenant(entry.getKey(),
                                                                       tenant.issuer(),
                                                                       tenant.endpoints(),
                                                                       OidcEndpointUris.redirectionEndpointUri(
                                                                               authorizationCode)));
    }

    private static boolean mayShareIssuer(AuthorizationCodeTenant first, AuthorizationCodeTenant second) {
        Optional<String> firstIssuer = first.issuer();
        Optional<String> secondIssuer = second.issuer();
        if (firstIssuer.isPresent() && secondIssuer.isPresent()) {
            return firstIssuer.equals(secondIssuer);
        }
        if (firstIssuer.isPresent()) {
            return second.endpoints().wellKnownUri()
                    .filter(uri -> OidcEndpointUris.wellKnownUriMatchesIssuer(uri, firstIssuer.orElseThrow()))
                    .isPresent();
        }
        if (secondIssuer.isPresent()) {
            return first.endpoints().wellKnownUri()
                    .filter(uri -> OidcEndpointUris.wellKnownUriMatchesIssuer(uri, secondIssuer.orElseThrow()))
                    .isPresent();
        }
        return first.endpoints().wellKnownUri().equals(second.endpoints().wellKnownUri());
    }

    private static boolean differentAuthorizationServers(AuthorizationCodeTenant first, AuthorizationCodeTenant second) {
        Optional<String> firstIssuer = first.issuer();
        Optional<String> secondIssuer = second.issuer();
        return firstIssuer.isEmpty() || secondIssuer.isEmpty() || !firstIssuer.equals(secondIssuer)
                || differentEndpoints(first, second);
    }

    private static boolean differentEndpoints(AuthorizationCodeTenant first, AuthorizationCodeTenant second) {
        return !first.endpoints().authorizationEndpointUri().equals(second.endpoints().authorizationEndpointUri())
                || !first.endpoints().tokenEndpointUri().equals(second.endpoints().tokenEndpointUri());
    }

    private static boolean redirectionEndpointsMayOverlap(AuthorizationCodeTenant first,
                                                           AuthorizationCodeTenant second) {
        URI firstUri = first.redirectionEndpointUri();
        URI secondUri = second.redirectionEndpointUri();
        if (!OidcUri.path(firstUri).equals(OidcUri.path(secondUri))) {
            return false;
        }
        if (!firstUri.isAbsolute() || !secondUri.isAbsolute()) {
            // A local URI obtains its origin from the request, so overlap with the other URI cannot be ruled out.
            return true;
        }
        return OidcUri.sameOrigin(firstUri, secondUri);
    }

    private record AuthorizationCodeTenant(String tenantId,
                                           Optional<String> issuer,
                                           OidcEndpointConfig endpoints,
                                           URI redirectionEndpointUri) {
    }
}
