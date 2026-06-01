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

import java.util.Optional;

import io.helidon.security.providers.common.OutboundTarget;

final class OidcOutboundPolicy {
    private final boolean tokenPropagation;
    private final boolean clientCredentialsGrant;
    private final String audience;

    private OidcOutboundPolicy(boolean tokenPropagation, boolean clientCredentialsGrant, String audience) {
        this.tokenPropagation = tokenPropagation;
        this.clientCredentialsGrant = clientCredentialsGrant;
        this.audience = audience;
    }

    static OidcOutboundPolicy tokenPropagation() {
        return tokenPropagation(null);
    }

    static OidcOutboundPolicy tokenPropagation(String audience) {
        return new OidcOutboundPolicy(true, false, audience);
    }

    static OidcOutboundPolicy clientCredentialsGrant() {
        return new OidcOutboundPolicy(false, true, null);
    }

    static OidcOutboundPolicy tokenPropagationAndClientCredentialsGrant() {
        return new OidcOutboundPolicy(true, true, null);
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
            return Optional.of(clientCredentialsGrant());
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
}
