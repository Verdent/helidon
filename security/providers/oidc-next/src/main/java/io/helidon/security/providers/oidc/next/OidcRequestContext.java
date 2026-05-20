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

import java.util.List;
import java.util.Optional;

import io.helidon.security.EndpointConfig;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;

final class OidcRequestContext {
    private static final String AUTHORIZATION = "Authorization";
    private static final String ACCESS_TOKEN = "access_token";
    private static final String BEARER_PREFIX = "Bearer ";

    private final ProviderRequest providerRequest;
    private final OidcProviderConfig config;

    private OidcRequestContext(ProviderRequest providerRequest, OidcProviderConfig config) {
        this.providerRequest = providerRequest;
        this.config = config;
    }

    static OidcRequestContext create(ProviderRequest providerRequest, OidcProviderConfig config) {
        return new OidcRequestContext(providerRequest, config);
    }

    Optional<OidcEndpointPolicy> endpointPolicy() {
        EndpointConfig endpointConfig = endpointConfig();
        if (endpointConfig == null) {
            return OidcConfigSupport.endpointPolicy(config);
        }
        return endpointConfig.instance(OidcEndpointPolicy.class)
                .or(() -> OidcConfigSupport.endpointPolicy(config));
    }

    boolean bearerTokenPresent() {
        OidcTokenTransportConfig tokenTransport = tokenTransport();
        return (tokenTransport.authorizationHeaderEnabled() && bearerTokenHeaderPresent())
                || (tokenTransport.queryParameterEnabled() && accessTokenQueryParameterPresent());
    }

    boolean authorizationResponsePresent() {
        return environment().queryParams().contains("state")
                && (environment().queryParams().contains("code") || environment().queryParams().contains("error"));
    }

    private boolean bearerTokenHeaderPresent() {
        List<String> values = environment().headers().getOrDefault(AUTHORIZATION, List.of());
        for (String value : values) {
            if (value.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())
                    && value.length() > BEARER_PREFIX.length()) {
                return true;
            }
        }
        return false;
    }

    private boolean accessTokenQueryParameterPresent() {
        return environment().queryParams()
                .first(ACCESS_TOKEN)
                .asOptional()
                .filter(token -> !token.isBlank())
                .isPresent();
    }

    private OidcTokenTransportConfig tokenTransport() {
        return OidcConfigSupport.tokenTransport(config)
                .orElseGet(OidcTokenTransportConfig::create);
    }

    private EndpointConfig endpointConfig() {
        return providerRequest.endpointConfig();
    }

    private SecurityEnvironment environment() {
        return providerRequest.env();
    }
}
