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
    private final String audience;
    private final String clientCredentialsScope;

    private OidcOutboundPolicy(boolean tokenPropagation,
                               boolean clientCredentialsGrant,
                               String audience,
                               String clientCredentialsScope) {
        this.tokenPropagation = tokenPropagation;
        this.clientCredentialsGrant = clientCredentialsGrant;
        this.audience = audience;
        this.clientCredentialsScope = clientCredentialsScope;
    }

    static OidcOutboundPolicy tokenPropagation() {
        return tokenPropagation(null);
    }

    static OidcOutboundPolicy tokenPropagation(String audience) {
        return new OidcOutboundPolicy(true, false, audience, null);
    }

    static OidcOutboundPolicy clientCredentialsGrant() {
        return clientCredentialsGrant(List.of());
    }

    static OidcOutboundPolicy clientCredentialsGrant(List<String> scopes) {
        String scope = OidcConfigSupport.clientCredentialsScope(scopes);
        return new OidcOutboundPolicy(false, true, null, scope.isEmpty() ? null : scope);
    }

    static OidcOutboundPolicy tokenPropagationAndClientCredentialsGrant() {
        return new OidcOutboundPolicy(true, true, null, null);
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
            return Optional.of(tokenPropagation(config.audience().orElse(null)));
        }
        if (config.clientCredentialsGrantEnabled()) {
            return Optional.of(clientCredentialsGrant(config.clientCredentialsScopes()));
        }
        return Optional.empty();
    }

    boolean tokenPropagationEnabled() {
        return tokenPropagation;
    }

    boolean clientCredentialsGrantEnabled() {
        return clientCredentialsGrant;
    }

    Optional<String> audience() {
        return Optional.ofNullable(audience);
    }

    Optional<String> clientCredentialsScope() {
        return Optional.ofNullable(clientCredentialsScope);
    }
}
