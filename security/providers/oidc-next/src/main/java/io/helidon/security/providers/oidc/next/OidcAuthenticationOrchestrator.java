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

import io.helidon.security.AuthenticationResponse;

final class OidcAuthenticationOrchestrator {
    private final OidcProviderConfig config;
    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;
    private final OidcRequestClassifier classifier;
    private final OidcResponseFactory responseFactory;

    private OidcAuthenticationOrchestrator(OidcProviderConfig config,
                                           OidcTenantRuntimeRegistry tenantRuntimeRegistry,
                                           OidcRequestClassifier classifier,
                                           OidcResponseFactory responseFactory) {
        this.config = config;
        this.tenantRuntimeRegistry = tenantRuntimeRegistry;
        this.classifier = classifier;
        this.responseFactory = responseFactory;
    }

    static OidcAuthenticationOrchestrator create(OidcProviderConfig config,
                                                 OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcAuthenticationOrchestrator(config,
                                                  tenantRuntimeRegistry,
                                                  OidcRequestClassifier.create(),
                                                  OidcResponseFactory.create());
    }

    AuthenticationResponse authenticate(io.helidon.security.ProviderRequest providerRequest) {
        if (providerRequest == null) {
            return AuthenticationResponse.abstain();
        }

        OidcRequestContext context = OidcRequestContext.create(providerRequest, tenantRuntimeRegistry);
        if (context.tenantContext().filter(it -> !it.ready()).isPresent()) {
            return responseFactory.tenantUnavailable(context.tenantContext().orElseThrow());
        }

        OidcProtocolOperation operation = classifier.classify(context);

        return switch (operation) {
            case BEARER_TOKEN_INVALID_REQUEST -> responseFactory.invalidBearerTokenRequest(
                    context.bearerTokenErrorDescription());
            case BEARER_TOKEN_AUTHENTICATION -> authenticateBearerToken(context);
            case AUTHORIZATION_CODE_FLOW_INITIATION -> responseFactory.authorizationCodeFlowNotImplemented();
            case AUTHORIZATION_RESPONSE, RP_INITIATED_LOGOUT -> AuthenticationResponse.abstain();
            case TOKEN_PROPAGATION, CLIENT_CREDENTIALS_GRANT -> AuthenticationResponse.abstain();
            case AMBIGUOUS -> responseFactory.ambiguousRequest();
            case ABSTAIN -> AuthenticationResponse.abstain();
        };
    }

    private AuthenticationResponse authenticateBearerToken(OidcRequestContext context) {
        if (context.bearerTokenEvidence().isPresent()) {
            return responseFactory.bearerTokenValidationNotImplemented();
        }
        if (config.optional()) {
            return responseFactory.optional("Bearer Token is required");
        }
        return responseFactory.missingBearerToken();
    }
}
