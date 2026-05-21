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

import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;

final class OidcOutboundOrchestrator {
    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;
    private final OidcRequestClassifier classifier;
    private final OidcResponseFactory responseFactory;

    private OidcOutboundOrchestrator(OidcTenantRuntimeRegistry tenantRuntimeRegistry,
                                     OidcRequestClassifier classifier,
                                     OidcResponseFactory responseFactory) {
        this.tenantRuntimeRegistry = tenantRuntimeRegistry;
        this.classifier = classifier;
        this.responseFactory = responseFactory;
    }

    static OidcOutboundOrchestrator create(OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcOutboundOrchestrator(tenantRuntimeRegistry,
                                            OidcRequestClassifier.create(),
                                            OidcResponseFactory.create());
    }

    boolean isSupported(ProviderRequest providerRequest,
                        SecurityEnvironment outboundEnv,
                        EndpointConfig outboundConfig) {
        return tenantRuntimeRegistry.tenantConfig(providerRequest)
                .map(tenantConfig -> {
                    if (outboundConfig != null && outboundConfig.instance(OidcOutboundPolicy.class).isPresent()) {
                        return true;
                    }
                    return OidcConfigSupport.outboundPolicy(tenantConfig).isPresent();
                })
                .orElse(false);
    }

    OutboundSecurityResponse secure(ProviderRequest providerRequest,
                                    SecurityEnvironment outboundEnv,
                                    EndpointConfig outboundConfig) {
        OidcOutboundRequestContext context = OidcOutboundRequestContext.create(providerRequest,
                                                                               outboundConfig,
                                                                               tenantRuntimeRegistry);
        if (context.tenantContext().filter(it -> !it.ready()).isPresent()) {
            return responseFactory.tenantUnavailableForOutbound(context.tenantContext().orElseThrow());
        }

        OidcProtocolOperation operation = classifier.classify(context);

        return switch (operation) {
            case TOKEN_PROPAGATION -> responseFactory.tokenPropagationNotImplemented();
            case CLIENT_CREDENTIALS_GRANT -> responseFactory.clientCredentialsGrantNotImplemented();
            case AMBIGUOUS -> responseFactory.ambiguousOutboundRequest();
            case BEARER_TOKEN_INVALID_REQUEST,
                    BEARER_TOKEN_AUTHENTICATION,
                    AUTHORIZATION_CODE_FLOW_INITIATION,
                    AUTHORIZATION_RESPONSE,
                    RP_INITIATED_LOGOUT,
                    ABSTAIN -> OutboundSecurityResponse.abstain();
        };
    }
}
