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
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.helidon.common.socket.PeerInfo;
import io.helidon.http.HeaderNames;
import io.helidon.security.EndpointConfig;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;

final class OidcRequestContext {
    private final ProviderRequest providerRequest;
    private final Optional<OidcTenantContext> tenantContext;
    private final Optional<OidcEndpointPolicy> endpointPolicy;
    private OidcBearerTokenExtractionResult bearerTokenExtractionResult;
    private Map<String, List<String>> cookies;

    OidcRequestContext(ProviderRequest providerRequest,
                       OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this(providerRequest, tenantRuntimeRegistry.tenantContext(providerRequest));
    }

    private OidcRequestContext(ProviderRequest providerRequest,
                               Optional<OidcTenantContext> tenantContext) {
        this(providerRequest,
             tenantContext,
             tenantContext.filter(OidcTenantContext::ready)
                     .flatMap(tenant -> resolveEndpointPolicy(providerRequest, tenant.tenantConfig())));
    }

    OidcRequestContext(ProviderRequest providerRequest,
                       Optional<OidcTenantContext> tenantContext,
                       Optional<OidcEndpointPolicy> endpointPolicy) {
        this.providerRequest = providerRequest;
        this.tenantContext = tenantContext;
        this.endpointPolicy = endpointPolicy;
    }

    Optional<OidcEndpointPolicy> endpointPolicy() {
        return tenantContext.filter(OidcTenantContext::ready).flatMap(_ -> endpointPolicy);
    }

    static Optional<OidcEndpointPolicy> resolveEndpointPolicy(ProviderRequest providerRequest,
                                                              OidcTenantConfig tenantConfig) {
        EndpointConfig endpointConfig = providerRequest.endpointConfig();
        if (endpointConfig == null) {
            return OidcEndpointPolicyResolver.resolve(tenantConfig);
        }
        return endpointConfigInstance(endpointConfig, OidcEndpointPolicy.class)
                .or(() -> endpointConfigInstance(endpointConfig, OidcEndpointPolicyConfig.class)
                        .flatMap(config -> OidcEndpointPolicyResolver.resolve(tenantConfig, config)))
                .or(() -> OidcEndpointPolicyResolver.resolve(tenantConfig));
    }

    Optional<OidcTenantContext> tenantContext() {
        return tenantContext;
    }

    String bearerChallengeRealm() {
        return tenantContext
                .map(OidcTenantContext::bearerChallengeRealm)
                .orElse(OidcResponseFactory.DEFAULT_CHALLENGE_REALM);
    }

    boolean bearerTokenPresent() {
        return bearerToken().isPresent();
    }

    Optional<String> bearerToken() {
        return bearerTokenExtractionResult().bearerToken();
    }

    boolean bearerTokenInvalidRequest() {
        return bearerTokenExtractionResult().invalidRequest();
    }

    String bearerTokenErrorDescription() {
        return bearerTokenExtractionResult()
                .errorDescription()
                .orElse("Bearer Token request is invalid");
    }

    SecurityEnvironment environment() {
        return providerRequest.env();
    }

    Optional<Certificate> peerCertificate() {
        return environment()
                .abacAttribute("remotePeer")
                .filter(PeerInfo.class::isInstance)
                .map(PeerInfo.class::cast)
                .flatMap(PeerInfo::tlsCertificates)
                .filter(certificates -> certificates.length > 0)
                .map(certificates -> certificates[0]);
    }

    List<String> cookieValues(String name) {
        return cookies().getOrDefault(name, List.of());
    }

    Map<String, List<String>> cookies() {
        if (cookies != null) {
            return cookies;
        }
        Map<String, List<String>> parsedCookies = new LinkedHashMap<>();
        for (String cookieHeaderValue : environment().headers()
                .getOrDefault(HeaderNames.COOKIE.defaultCase(), List.of())) {
            parseCookieHeader(cookieHeaderValue, parsedCookies);
        }
        cookies = Map.copyOf(parsedCookies);
        return cookies;
    }

    boolean redirectionEndpointRequest(List<URI> redirectionEndpointUris) {
        URI targetUri = environment().targetUri();
        // Route recognition is not response validation: malformed callbacks must also reach the HTTP feature.
        return targetUri != null
                && "GET".equals(environment().method())
                && redirectionEndpointUris.stream()
                        .anyMatch(uri -> OidcEndpointUris.redirectionEndpointMatches(targetUri,
                                                                                    environment().queryParams(),
                                                                                    targetUri.resolve(uri)));
    }

    private static <T> Optional<T> endpointConfigInstance(EndpointConfig endpointConfig, Class<T> clazz) {
        Optional<T> exactInstance = endpointConfig.instance(clazz);
        if (exactInstance.isPresent()) {
            return exactInstance;
        }
        return endpointConfig.instanceKeys()
                .stream()
                .filter(clazz::isAssignableFrom)
                .map(endpointConfig::instance)
                .flatMap(Optional::stream)
                .map(clazz::cast)
                .findFirst();
    }

    private void parseCookieHeader(String headerValue, Map<String, List<String>> result) {
        for (String token : headerValue.split(";")) {
            int valueStart = token.indexOf('=');
            if (valueStart <= 0) {
                continue;
            }
            String name = token.substring(0, valueStart).trim();
            if (name.isEmpty()) {
                continue;
            }
            String value = token.substring(valueStart + 1).trim();
            result.computeIfAbsent(name, _ -> new ArrayList<>(1))
                    .add(value);
        }
    }

    private OidcBearerTokenExtractionResult bearerTokenExtractionResult() {
        if (bearerTokenExtractionResult != null) {
            return bearerTokenExtractionResult;
        }
        if (endpointPolicy().filter(OidcEndpointPolicy::bearerTokenAuthenticationEnabled).isEmpty()) {
            bearerTokenExtractionResult = OidcBearerTokenExtractionResult.empty();
            return bearerTokenExtractionResult;
        }
        OidcTokenTransportConfig tokenTransport = tenantContext
                .map(OidcTenantContext::tokenTransport)
                .orElseGet(OidcTokenTransportConfig::create);
        bearerTokenExtractionResult = OidcBearerTokenExtractor.extract(environment(), tokenTransport);
        return bearerTokenExtractionResult;
    }
}
