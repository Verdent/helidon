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
import java.util.Optional;
import java.util.Set;

final class OidcEndpointPolicyResolver {
    private OidcEndpointPolicyResolver() {
    }

    static Optional<OidcEndpointPolicy> resolve(OidcTenantConfig tenant) {
        return resolve(tenant, tenant.endpointPolicy());
    }

    static Optional<OidcEndpointPolicy> resolve(OidcTenantConfig tenant,
                                                OidcEndpointPolicyConfig endpointPolicy) {
        boolean bearerTokenSupported = bearerTokenSupported(tenant.protectedResource());
        boolean authenticationCookieSupported = authenticationCookieSupported(tenant.authorizationCode());
        EnumSet<OidcEndpointCredential> acceptedCredentials = resolvedAcceptedCredentials(endpointPolicy,
                                                                                          bearerTokenSupported,
                                                                                          authenticationCookieSupported);
        if (acceptedCredentials.isEmpty()) {
            return Optional.empty();
        }
        OidcAuthenticationFailureResponse failureResponse = resolvedFailureResponse(endpointPolicy,
                                                                                    acceptedCredentials);
        validateResolvedEndpointPolicy(acceptedCredentials,
                                       failureResponse,
                                       bearerTokenSupported,
                                       authenticationCookieSupported);
        return Optional.of(OidcEndpointPolicy.create(acceptedCredentials, failureResponse));
    }

    static void validate(Optional<OidcProtectedResourceConfig> protectedResource,
                         Optional<OidcAuthorizationCodeConfig> authorizationCode,
                         OidcEndpointPolicyConfig endpointPolicy) {
        boolean bearerTokenSupported = bearerTokenSupported(protectedResource);
        boolean authenticationCookieSupported = authenticationCookieSupported(authorizationCode);
        EnumSet<OidcEndpointCredential> acceptedCredentials = resolvedAcceptedCredentials(endpointPolicy,
                                                                                          bearerTokenSupported,
                                                                                          authenticationCookieSupported);
        if (acceptedCredentials.isEmpty()) {
            endpointPolicy.authenticationFailureResponse()
                    .ifPresent(_ -> {
                        throw new IllegalArgumentException(
                                "endpoint-policy requires Protected Resource or Authorization Code Flow to be enabled");
                    });
            return;
        }
        validateResolvedEndpointPolicy(acceptedCredentials,
                                       resolvedFailureResponse(endpointPolicy, acceptedCredentials),
                                       bearerTokenSupported,
                                       authenticationCookieSupported);
    }

    private static boolean bearerTokenSupported(Optional<OidcProtectedResourceConfig> protectedResource) {
        return protectedResource
                .filter(OidcProtectedResourceConfig::enabled)
                .isPresent();
    }

    private static boolean authenticationCookieSupported(Optional<OidcAuthorizationCodeConfig> authorizationCode) {
        return authorizationCode
                .filter(OidcAuthorizationCodeConfig::enabled)
                .isPresent();
    }

    private static EnumSet<OidcEndpointCredential> resolvedAcceptedCredentials(OidcEndpointPolicyConfig endpointPolicy,
                                                                              boolean bearerTokenSupported,
                                                                              boolean authenticationCookieSupported) {
        EnumSet<OidcEndpointCredential> acceptedCredentials = EnumSet.noneOf(OidcEndpointCredential.class);
        if (!endpointPolicy.acceptedCredentials().isEmpty()) {
            acceptedCredentials.addAll(endpointPolicy.acceptedCredentials());
            return acceptedCredentials;
        }
        if (bearerTokenSupported) {
            acceptedCredentials.add(OidcEndpointCredential.BEARER_TOKEN);
        }
        if (authenticationCookieSupported) {
            acceptedCredentials.add(OidcEndpointCredential.AUTHENTICATION_COOKIE);
        }
        return acceptedCredentials;
    }

    private static OidcAuthenticationFailureResponse resolvedFailureResponse(
            OidcEndpointPolicyConfig endpointPolicy,
            Set<OidcEndpointCredential> acceptedCredentials) {
        return endpointPolicy.authenticationFailureResponse()
                .orElseGet(() -> acceptedCredentials.size() == 1
                        && acceptedCredentials.contains(OidcEndpointCredential.AUTHENTICATION_COOKIE)
                        ? OidcAuthenticationFailureResponse.AUTHORIZATION_CODE_REDIRECT
                        : OidcAuthenticationFailureResponse.UNAUTHORIZED);
    }

    private static void validateResolvedEndpointPolicy(Set<OidcEndpointCredential> acceptedCredentials,
                                                       OidcAuthenticationFailureResponse failureResponse,
                                                       boolean bearerTokenSupported,
                                                       boolean authenticationCookieSupported) {
        if (acceptedCredentials.contains(OidcEndpointCredential.BEARER_TOKEN) && !bearerTokenSupported) {
            throw new IllegalArgumentException(
                    "endpoint-policy.accepted-credentials bearer-token requires protected-resource to be enabled");
        }
        if (acceptedCredentials.contains(OidcEndpointCredential.AUTHENTICATION_COOKIE)
                && !authenticationCookieSupported) {
            throw new IllegalArgumentException(
                    "endpoint-policy.accepted-credentials authentication-cookie requires authorization-code to be enabled");
        }
        if (failureResponse == OidcAuthenticationFailureResponse.AUTHORIZATION_CODE_REDIRECT) {
            if (!authenticationCookieSupported) {
                throw new IllegalArgumentException(
                        "endpoint-policy.authentication-failure-response authorization-code-redirect requires "
                                + "authorization-code to be enabled");
            }
            if (!acceptedCredentials.contains(OidcEndpointCredential.AUTHENTICATION_COOKIE)) {
                throw new IllegalArgumentException(
                        "endpoint-policy.authentication-failure-response authorization-code-redirect requires "
                                + "accepted-credentials to include authentication-cookie");
            }
        }
    }
}
