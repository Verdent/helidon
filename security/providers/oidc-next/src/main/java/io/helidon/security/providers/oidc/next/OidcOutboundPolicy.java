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

import io.helidon.security.providers.common.OutboundTarget;

final class OidcOutboundPolicy {
    private final boolean tokenPropagation;
    private final boolean clientCredentialsGrant;
    private final boolean tokenExchange;
    private final String audience;
    private final boolean audienceValidation;
    private final String clientCredentialsScope;
    private final List<String> clientCredentialsResources;
    private final String tokenExchangeScope;
    private final String tokenExchangeResource;
    private final String tokenExchangeAudience;

    private OidcOutboundPolicy(boolean tokenPropagation,
                               boolean clientCredentialsGrant,
                               boolean tokenExchange,
                               String audience,
                               boolean audienceValidation,
                               String clientCredentialsScope,
                               List<String> clientCredentialsResources,
                               String tokenExchangeScope,
                               String tokenExchangeResource,
                               String tokenExchangeAudience) {
        this.tokenPropagation = tokenPropagation;
        this.clientCredentialsGrant = clientCredentialsGrant;
        this.tokenExchange = tokenExchange;
        this.audience = audience;
        this.audienceValidation = audienceValidation;
        this.clientCredentialsScope = clientCredentialsScope;
        this.clientCredentialsResources = List.copyOf(clientCredentialsResources);
        this.tokenExchangeScope = tokenExchangeScope;
        this.tokenExchangeResource = tokenExchangeResource;
        this.tokenExchangeAudience = tokenExchangeAudience;
    }

    static OidcOutboundPolicy tokenPropagation() {
        return tokenPropagation(null);
    }

    static OidcOutboundPolicy tokenPropagation(String audience) {
        return tokenPropagation(audience, true);
    }

    static OidcOutboundPolicy tokenPropagation(String audience, boolean audienceValidation) {
        return new OidcOutboundPolicy(true, false, false, audience, audienceValidation, null, List.of(),
                                      null, null, null);
    }

    static OidcOutboundPolicy clientCredentialsGrant() {
        return clientCredentialsGrant(List.of(), List.of());
    }

    static OidcOutboundPolicy clientCredentialsGrant(List<String> scopes) {
        return clientCredentialsGrant(scopes, List.of());
    }

    static OidcOutboundPolicy clientCredentialsGrant(List<String> scopes, List<String> resources) {
        String scope = OidcConfigSupport.clientCredentialsScope(scopes);
        return new OidcOutboundPolicy(false, true, false, null, false, scope.isEmpty() ? null : scope, resources,
                                      null, null, null);
    }

    static OidcOutboundPolicy tokenExchange(String resource, String audience) {
        return tokenExchange(List.of(), resource, audience);
    }

    static OidcOutboundPolicy tokenExchange(List<String> scopes, String resource, String audience) {
        String scope = OidcConfigSupport.tokenExchangeScope(scopes);
        return new OidcOutboundPolicy(false, false, true, null, false, null, List.of(),
                                      scope.isEmpty() ? null : scope, resource, audience);
    }

    static OidcOutboundPolicy tokenPropagationAndClientCredentialsGrant() {
        return new OidcOutboundPolicy(true, true, false, null, true, null, List.of(), null, null, null);
    }

    static Optional<OidcOutboundPolicy> fromTarget(OutboundTarget target) {
        return target.customObject(OidcOutboundTargetConfig.class)
                .flatMap(OidcOutboundPolicy::fromTargetConfig)
                .or(() -> target.getConfig()
                        .map(OidcOutboundTargetConfig::create)
                        .flatMap(OidcOutboundPolicy::fromTargetConfig));
    }

    static Optional<OidcOutboundPolicy> fromTargetConfig(OidcOutboundTargetConfig config) {
        if (config.tokenPropagationEnabled()) {
            return Optional.of(tokenPropagation(config.audience().orElse(null), config.audienceValidationEnabled()));
        }
        if (config.clientCredentialsGrantEnabled()) {
            return Optional.of(clientCredentialsGrant(config.clientCredentialsScopes(),
                                                      config.clientCredentialsResources()));
        }
        if (config.tokenExchangeEnabled()) {
            return Optional.of(tokenExchange(config.tokenExchangeScopes(),
                                             config.tokenExchangeResource().orElse(null),
                                             config.tokenExchangeAudience().orElse(null)));
        }
        return Optional.empty();
    }

    boolean tokenPropagationEnabled() {
        return tokenPropagation;
    }

    boolean clientCredentialsGrantEnabled() {
        return clientCredentialsGrant;
    }

    boolean tokenExchangeEnabled() {
        return tokenExchange;
    }

    int strategyCount() {
        int count = tokenPropagation ? 1 : 0;
        count += clientCredentialsGrant ? 1 : 0;
        count += tokenExchange ? 1 : 0;
        return count;
    }

    Optional<String> audience() {
        return Optional.ofNullable(audience);
    }

    boolean audienceValidationEnabled() {
        return audienceValidation;
    }

    Optional<String> clientCredentialsScope() {
        return Optional.ofNullable(clientCredentialsScope);
    }

    List<String> clientCredentialsResources() {
        return clientCredentialsResources;
    }

    Optional<String> tokenExchangeScope() {
        return Optional.ofNullable(tokenExchangeScope);
    }

    Optional<String> tokenExchangeResource() {
        return Optional.ofNullable(tokenExchangeResource);
    }

    Optional<String> tokenExchangeAudience() {
        return Optional.ofNullable(tokenExchangeAudience);
    }
}
