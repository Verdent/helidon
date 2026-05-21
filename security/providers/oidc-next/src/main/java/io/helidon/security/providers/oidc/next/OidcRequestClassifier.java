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

final class OidcRequestClassifier {
    private OidcRequestClassifier() {
    }

    static OidcRequestClassifier create() {
        return new OidcRequestClassifier();
    }

    OidcProtocolOperation classify(OidcRequestContext context) {
        if (context.bearerTokenInvalidRequest()) {
            return OidcProtocolOperation.BEARER_TOKEN_INVALID_REQUEST;
        }

        if (context.bearerTokenPresent()) {
            return OidcProtocolOperation.BEARER_TOKEN_AUTHENTICATION;
        }

        if (context.authorizationResponsePresent()) {
            return OidcProtocolOperation.AUTHORIZATION_RESPONSE;
        }

        return context.endpointPolicy()
                .map(this::classifyEndpointPolicy)
                .orElse(OidcProtocolOperation.ABSTAIN);
    }

    OidcProtocolOperation classify(Optional<OidcOutboundPolicy> outboundPolicy) {
        return outboundPolicy
                .map(this::classifyOutboundPolicy)
                .orElse(OidcProtocolOperation.ABSTAIN);
    }

    private OidcProtocolOperation classifyEndpointPolicy(OidcEndpointPolicy policy) {
        if (policy.bearerTokenAuthenticationEnabled() && policy.authorizationCodeFlowEnabled()) {
            return OidcProtocolOperation.AMBIGUOUS;
        }
        if (policy.bearerTokenAuthenticationEnabled()) {
            return OidcProtocolOperation.BEARER_TOKEN_AUTHENTICATION;
        }
        if (policy.authorizationCodeFlowEnabled()) {
            return OidcProtocolOperation.AUTHORIZATION_CODE_FLOW_INITIATION;
        }
        return OidcProtocolOperation.ABSTAIN;
    }

    private OidcProtocolOperation classifyOutboundPolicy(OidcOutboundPolicy policy) {
        if (policy.tokenPropagationEnabled() && policy.clientCredentialsGrantEnabled()) {
            return OidcProtocolOperation.AMBIGUOUS;
        }
        if (policy.tokenPropagationEnabled()) {
            return OidcProtocolOperation.TOKEN_PROPAGATION;
        }
        if (policy.clientCredentialsGrantEnabled()) {
            return OidcProtocolOperation.CLIENT_CREDENTIALS_GRANT;
        }
        return OidcProtocolOperation.ABSTAIN;
    }
}
