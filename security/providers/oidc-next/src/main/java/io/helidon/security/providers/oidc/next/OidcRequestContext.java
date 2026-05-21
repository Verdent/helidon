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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.helidon.http.HeaderNames;
import io.helidon.security.EndpointConfig;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;

final class OidcRequestContext {
    private final ProviderRequest providerRequest;
    private final Optional<OidcTenantContext> tenantContext;
    private OidcBearerTokenExtractionResult bearerTokenExtractionResult;
    private Map<String, List<String>> cookies;

    private OidcRequestContext(ProviderRequest providerRequest,
                               OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this.providerRequest = providerRequest;
        this.tenantContext = tenantRuntimeRegistry.tenantContext(providerRequest);
    }

    static OidcRequestContext create(ProviderRequest providerRequest,
                                     OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcRequestContext(providerRequest, tenantRuntimeRegistry);
    }

    Optional<OidcEndpointPolicy> endpointPolicy() {
        if (tenantContext.filter(OidcTenantContext::ready).isEmpty()) {
            return Optional.empty();
        }

        EndpointConfig endpointConfig = endpointConfig();
        if (endpointConfig == null) {
            return tenantContext.flatMap(OidcTenantContext::endpointPolicy);
        }
        return endpointConfig.instance(OidcEndpointPolicy.class)
                .or(() -> tenantContext.flatMap(OidcTenantContext::endpointPolicy));
    }

    Optional<OidcTenantContext> tenantContext() {
        return tenantContext;
    }

    boolean bearerTokenPresent() {
        return bearerTokenEvidence().isPresent();
    }

    Optional<OidcBearerTokenEvidence> bearerTokenEvidence() {
        return bearerTokenExtractionResult().evidence();
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

    List<String> cookieValues(String name) {
        return cookies().getOrDefault(name, List.of());
    }

    private Map<String, List<String>> cookies() {
        if (cookies != null) {
            return cookies;
        }
        Map<String, List<String>> parsedCookies = new LinkedHashMap<>();
        for (String cookieHeaderValue : headerValues(HeaderNames.COOKIE.defaultCase())) {
            parseCookieHeader(cookieHeaderValue, parsedCookies);
        }
        cookies = Map.copyOf(parsedCookies);
        return cookies;
    }

    private List<String> headerValues(String name) {
        List<String> exact = environment().headers().get(name);
        if (exact != null) {
            return exact;
        }
        List<String> values = new ArrayList<>();
        environment().headers()
                .forEach((headerName, headerValues) -> {
                    if (name.equalsIgnoreCase(headerName)) {
                        values.addAll(headerValues);
                    }
                });
        return values;
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
            result.computeIfAbsent(name, ignored -> new ArrayList<>(1))
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
        bearerTokenExtractionResult = OidcBearerTokenExtractor.extract(environment(), tokenTransport());
        return bearerTokenExtractionResult;
    }

    boolean authorizationResponsePresent() {
        return environment().queryParams().contains("state")
                && (environment().queryParams().contains("code") || environment().queryParams().contains("error"));
    }

    private OidcTokenTransportConfig tokenTransport() {
        return tenantContext
                .map(OidcTenantContext::tokenTransport)
                .orElseGet(OidcTokenTransportConfig::create);
    }

    private EndpointConfig endpointConfig() {
        return providerRequest.endpointConfig();
    }

}
