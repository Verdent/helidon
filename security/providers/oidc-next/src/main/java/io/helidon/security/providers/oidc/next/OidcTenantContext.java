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

import io.helidon.webclient.api.WebClient;

final class OidcTenantContext {
    private final String tenantId;
    private final OidcTenantConfig tenantConfig;
    private final OidcTenantState state;
    private final Optional<RuntimeResources> runtimeResources;
    private final Throwable failureCause;

    private OidcTenantContext(String tenantId,
                              OidcTenantConfig tenantConfig,
                              OidcTenantState state,
                              OidcProviderMetadata readyMetadata,
                              WebClient readyWebClient,
                              Throwable failureCause) {
        this.tenantId = tenantId;
        this.tenantConfig = tenantConfig;
        this.state = state;
        this.runtimeResources = state == OidcTenantState.READY
                ? Optional.of(RuntimeResources.create(tenantId, tenantConfig, readyMetadata, readyWebClient))
                : Optional.empty();
        this.failureCause = failureCause;
    }

    static OidcTenantContext ready(String tenantId, OidcTenantConfig tenantConfig) {
        return ready(tenantId,
                     tenantConfig,
                     OidcProviderMetadata.fromStaticConfig(tenantConfig),
                     OidcWebClientFactory.create(tenantConfig));
    }

    static OidcTenantContext ready(String tenantId, OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        return ready(tenantId, tenantConfig, metadata, OidcWebClientFactory.create(tenantConfig));
    }

    static OidcTenantContext ready(String tenantId,
                                   OidcTenantConfig tenantConfig,
                                   OidcProviderMetadata metadata,
                                   WebClient webClient) {
        return new OidcTenantContext(tenantId, tenantConfig, OidcTenantState.READY, metadata, webClient, null);
    }

    static OidcTenantContext disabled(String tenantId, OidcTenantConfig tenantConfig) {
        return new OidcTenantContext(tenantId, tenantConfig, OidcTenantState.DISABLED, null, null, null);
    }

    static OidcTenantContext failed(String tenantId, OidcTenantConfig tenantConfig) {
        return failed(tenantId, tenantConfig, null);
    }

    static OidcTenantContext failed(String tenantId, OidcTenantConfig tenantConfig, Throwable failureCause) {
        return new OidcTenantContext(tenantId, tenantConfig, OidcTenantState.FAILED, null, null, failureCause);
    }

    String tenantId() {
        return tenantId;
    }

    OidcTenantConfig tenantConfig() {
        return tenantConfig;
    }

    OidcTenantState state() {
        return state;
    }

    Optional<Throwable> failureCause() {
        return Optional.ofNullable(failureCause);
    }

    boolean ready() {
        return state == OidcTenantState.READY;
    }

    OidcProviderMetadata metadata() {
        return runtimeResources().metadata();
    }

    OidcEndpointClient endpointClient() {
        return runtimeResources().endpointClient();
    }

    Optional<OidcRequestObjectProcessor> requestObjectProcessor() {
        return runtimeResources().requestObjectProcessor();
    }

    OidcClientAuthenticationSupport introspectionClientAuthentication() {
        return runtimeResources().introspectionClientAuthentication();
    }

    OidcJwkSetManager jwkSetManager() {
        return runtimeResources().jwkSetManager();
    }

    WebClient webClient() {
        return runtimeResources().webClient();
    }

    OidcTokenValidationConfig tokenValidation() {
        runtimeResources();
        return tenantConfig.protectedResource()
                .map(OidcProtectedResourceConfig::tokenValidation)
                .orElseGet(OidcTokenValidationConfig::create);
    }

    OidcCookieStateHandler cookieStateHandler() {
        return runtimeResources().cookieStateHandler();
    }

    OidcIdTokenDecryptor idTokenDecryptor() {
        return runtimeResources().idTokenDecryptor();
    }

    Optional<OidcUserInfoJwtProcessor> userInfoJwtProcessor() {
        return runtimeResources().userInfoJwtProcessor();
    }

    Optional<OidcEndpointPolicy> endpointPolicy() {
        if (!ready()) {
            return Optional.empty();
        }
        return runtimeResources().endpointPolicy();
    }

    OidcTokenTransportConfig tokenTransport() {
        return tenantConfig.tokenTransport();
    }

    String bearerChallengeRealm() {
        return tenantConfig.protectedResource()
                .map(OidcProtectedResourceConfig::challengeRealm)
                .orElse(OidcProtectedResourceConfigBlueprint.DEFAULT_CHALLENGE_REALM);
    }

    OidcSubjectMappingConfig subjectMapping() {
        return tenantConfig.subjectMapping();
    }

    private RuntimeResources runtimeResources() {
        return runtimeResources.orElseThrow(() -> new IllegalStateException(
                "OIDC tenant runtime resources are available only when tenant is ready"));
    }

    private record RuntimeResources(Optional<OidcEndpointPolicy> endpointPolicy,
                                    OidcProviderMetadata metadata,
                                    OidcEndpointClient endpointClient,
                                    Optional<OidcRequestObjectProcessor> requestObjectProcessor,
                                    OidcClientAuthenticationSupport introspectionClientAuthentication,
                                    OidcJwkSetManager jwkSetManager,
                                    OidcIdTokenDecryptor idTokenDecryptor,
                                    Optional<OidcUserInfoJwtProcessor> userInfoJwtProcessor,
                                    OidcCookieStateHandler cookieStateHandler,
                                    WebClient webClient) {
        private static RuntimeResources create(String tenantId,
                                               OidcTenantConfig tenantConfig,
                                               OidcProviderMetadata metadata,
                                               WebClient webClient) {
            OidcIdTokenDecryptor idTokenDecryptor = OidcIdTokenDecryptor.create(tenantConfig);
            OidcJwkSetManager jwkSetManager = OidcJwkSetManager.create(tenantId,
                                                                      metadata,
                                                                      webClient,
                                                                      tenantConfig.jwkSet());
            return new RuntimeResources(OidcEndpointPolicyResolver.resolve(tenantConfig),
                                        metadata,
                                        new OidcEndpointClient(tenantConfig, metadata, webClient),
                                        OidcRequestObjectProcessor.create(tenantConfig, jwkSetManager),
                                        OidcClientAuthenticationSupport.introspectionEndpoint(tenantConfig),
                                        jwkSetManager,
                                        idTokenDecryptor,
                                        OidcUserInfoJwtProcessor.create(tenantConfig),
                                        OidcCookieStateHandler.create(tenantConfig.cookies()),
                                        webClient);
        }
    }
}
