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
import java.util.Objects;
import java.util.Optional;

import io.helidon.security.providers.common.OutboundTarget;

/**
 * Resolved outbound policy for a configured target or a single outbound request.
 * The public configuration is {@link OidcOutboundPolicyConfig}.
 */
final class OidcOutboundPolicy {
    private final OidcOutboundPolicyConfig config;
    private final Optional<String> clientCredentialsScope;
    private final Optional<String> tokenExchangeScope;

    private OidcOutboundPolicy(OidcOutboundPolicyConfig config) {
        this.config = Objects.requireNonNull(config);
        this.clientCredentialsScope = scope(config.clientCredentialsScopes());
        this.tokenExchangeScope = scope(config.tokenExchangeScopes());
    }

    static boolean targetClientCredentialsGrantEnabled(List<OutboundTarget> outboundTargets) {
        return outboundTargets.stream()
                .map(OidcOutboundPolicy::fromTarget)
                .flatMap(Optional::stream)
                .anyMatch(OidcOutboundPolicy::clientCredentialsGrantEnabled);
    }

    static boolean targetTokenExchangeEnabled(List<OutboundTarget> outboundTargets) {
        return outboundTargets.stream()
                .map(OidcOutboundPolicy::fromTarget)
                .flatMap(Optional::stream)
                .anyMatch(OidcOutboundPolicy::tokenExchangeEnabled);
    }

    static Optional<OidcOutboundPolicy> fromTarget(OutboundTarget target) {
        return target.customObject(OidcOutboundPolicyConfig.class)
                .flatMap(OidcOutboundPolicy::fromConfig)
                .or(() -> target.getConfig()
                        .map(OidcOutboundPolicyConfig::create)
                        .flatMap(OidcOutboundPolicy::fromConfig));
    }

    static Optional<OidcOutboundPolicy> fromConfig(OidcOutboundPolicyConfig config) {
        Objects.requireNonNull(config);
        if (config.tokenPropagationEnabled()
                || config.clientCredentialsGrantEnabled()
                || config.tokenExchangeEnabled()) {
            return Optional.of(new OidcOutboundPolicy(config));
        }
        return Optional.empty();
    }

    boolean tokenPropagationEnabled() {
        return config.tokenPropagationEnabled();
    }

    boolean clientCredentialsGrantEnabled() {
        return config.clientCredentialsGrantEnabled();
    }

    boolean tokenExchangeEnabled() {
        return config.tokenExchangeEnabled();
    }

    Optional<String> audience() {
        return config.audience();
    }

    boolean audienceValidationEnabled() {
        return config.audienceValidationEnabled();
    }

    Optional<String> clientCredentialsScope() {
        return clientCredentialsScope;
    }

    List<String> clientCredentialsResources() {
        return config.clientCredentialsResources();
    }

    Optional<String> tokenExchangeScope() {
        return tokenExchangeScope;
    }

    Optional<String> tokenExchangeResource() {
        return config.tokenExchangeResource();
    }

    Optional<String> tokenExchangeAudience() {
        return config.tokenExchangeAudience();
    }

    private static Optional<String> scope(List<String> scopes) {
        String serialized = OidcScopeSupport.serializeScopes(scopes);
        return serialized.isEmpty() ? Optional.empty() : Optional.of(serialized);
    }
}
