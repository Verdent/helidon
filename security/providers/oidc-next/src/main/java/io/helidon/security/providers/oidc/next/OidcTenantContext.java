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

import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Optional;

import io.helidon.webclient.api.WebClient;

final class OidcTenantContext {
    private final String tenantId;
    private final OidcTenantConfig tenantConfig;
    private final OidcCookieStateHandler cookieStateHandler;
    private final OidcTenantState state;
    private final Optional<RuntimeResources> runtimeResources;
    private final Throwable failureCause;
    private final boolean retryableFailure;

    private OidcTenantContext(String tenantId,
                              OidcTenantConfig tenantConfig,
                              OidcTenantState state,
                              OidcProviderMetadata readyMetadata,
                              WebClient readyWebClient,
                              Throwable failureCause,
                              boolean retryableFailure) {
        this.tenantId = tenantId;
        this.tenantConfig = tenantConfig;
        this.cookieStateHandler = OidcCookieStateHandler.create(tenantId, tenantConfig);
        this.state = state;
        this.runtimeResources = state == OidcTenantState.READY
                ? Optional.of(RuntimeResources.create(tenantId, tenantConfig, readyMetadata, readyWebClient))
                : Optional.empty();
        this.failureCause = failureCause;
        this.retryableFailure = retryableFailure;
    }

    private OidcTenantContext(String tenantId,
                              OidcTenantConfig tenantConfig,
                              OidcCookieStateHandler cookieStateHandler,
                              OidcTenantState state,
                              Optional<RuntimeResources> runtimeResources,
                              Throwable failureCause,
                              boolean retryableFailure) {
        this.tenantId = tenantId;
        this.tenantConfig = tenantConfig;
        this.cookieStateHandler = cookieStateHandler;
        this.state = state;
        this.runtimeResources = runtimeResources;
        this.failureCause = failureCause;
        this.retryableFailure = retryableFailure;
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
        return new OidcTenantContext(tenantId,
                                     tenantConfig,
                                     OidcTenantState.READY,
                                     metadata,
                                     webClient,
                                     null,
                                     false);
    }

    static OidcTenantContext disabled(String tenantId, OidcTenantConfig tenantConfig) {
        return new OidcTenantContext(tenantId,
                                     tenantConfig,
                                     OidcTenantState.DISABLED,
                                     null,
                                     null,
                                     null,
                                     false);
    }

    static OidcTenantContext failed(String tenantId, OidcTenantConfig tenantConfig) {
        return failed(tenantId, tenantConfig, null);
    }

    static OidcTenantContext failed(String tenantId, OidcTenantConfig tenantConfig, Throwable failureCause) {
        return failed(tenantId, tenantConfig, failureCause, false);
    }

    static OidcTenantContext retryableFailure(String tenantId,
                                              OidcTenantConfig tenantConfig,
                                              Throwable failureCause) {
        return failed(tenantId, tenantConfig, failureCause, true);
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

    boolean retryableFailure() {
        return retryableFailure;
    }

    OidcTenantContext withCookieStateHandler(OidcCookieStateHandler cookieStateHandler) {
        return new OidcTenantContext(tenantId,
                                     tenantConfig,
                                     cookieStateHandler,
                                     state,
                                     runtimeResources,
                                     failureCause,
                                     retryableFailure);
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

    OidcJwkSetManager accessTokenJwkSetManager() {
        RuntimeResources resources = runtimeResources();
        return resources.accessTokenJwkSetManager().orElse(resources.jwkSetManager());
    }

    OidcRemoteWorkLimiter introspectionRemoteWorkLimiter() {
        return runtimeResources().remoteWorkLimiters().introspection();
    }

    OidcRemoteWorkLimiter tokenExchangeRemoteWorkLimiter() {
        return runtimeResources().remoteWorkLimiters().tokenExchange();
    }

    OidcRemoteWorkLimiter clientCredentialsRemoteWorkLimiter() {
        return runtimeResources().remoteWorkLimiters().clientCredentials();
    }

    OidcRefreshCoordinator<OidcRefreshTokenManager.RefreshResult> refreshCoordinator() {
        return runtimeResources().refreshCoordinator()
                .orElseThrow(() -> new IllegalStateException(
                        "Refresh coordination is available only when Authorization Code Flow is configured"));
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
        runtimeResources();
        return cookieStateHandler;
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
                .orElse(OidcResponseFactory.DEFAULT_CHALLENGE_REALM);
    }

    OidcSubjectMappingConfig subjectMapping() {
        return tenantConfig.subjectMapping();
    }

    private static OidcTenantContext failed(String tenantId,
                                            OidcTenantConfig tenantConfig,
                                            Throwable failureCause,
                                            boolean retryableFailure) {
        return new OidcTenantContext(tenantId,
                                     tenantConfig,
                                     OidcTenantState.FAILED,
                                     null,
                                     null,
                                     failureCause,
                                     retryableFailure);
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
                                    Optional<OidcJwkSetManager> accessTokenJwkSetManager,
                                    OidcIdTokenDecryptor idTokenDecryptor,
                                    Optional<OidcUserInfoJwtProcessor> userInfoJwtProcessor,
                                    RemoteWorkLimiters remoteWorkLimiters,
                                    Optional<OidcRefreshCoordinator<OidcRefreshTokenManager.RefreshResult>> refreshCoordinator,
                                    WebClient webClient) {
        private static RuntimeResources create(String tenantId,
                                               OidcTenantConfig tenantConfig,
                                               OidcProviderMetadata metadata,
                                               WebClient webClient) {
            OidcIdTokenDecryptor idTokenDecryptor = OidcIdTokenDecryptor.create(tenantConfig);
            OidcEndpointClient endpointClient = new OidcEndpointClient(tenantConfig, metadata, webClient);
            OidcJwkSetManager jwkSetManager = OidcJwkSetManager.create(tenantId,
                                                                      metadata,
                                                                      webClient,
                                                                      Clock.systemUTC(),
                                                                      tenantConfig.jwkSet(),
                                                                      uri -> jwkSetAccessToken(tenantConfig,
                                                                                               uri,
                                                                                               webClient,
                                                                                               endpointClient));
            Optional<OidcJwkSetManager> accessTokenJwkSetManager = tenantConfig.protectedResource()
                    .map(OidcProtectedResourceConfig::tokenValidation)
                    .flatMap(OidcTokenValidationConfig::verificationJwk)
                    .map(resource -> OidcJwkSetManager.createLocal(tenantId, resource, Clock.systemUTC(), tenantConfig.jwkSet()));
            return new RuntimeResources(OidcEndpointPolicyResolver.resolve(tenantConfig),
                                        metadata,
                                        endpointClient,
                                        OidcRequestObjectProcessor.create(tenantConfig, jwkSetManager),
                                        OidcClientAuthenticationSupport.introspectionEndpoint(tenantConfig),
                                        jwkSetManager,
                                        accessTokenJwkSetManager,
                                        idTokenDecryptor,
                                        OidcUserInfoJwtProcessor.create(tenantConfig),
                                        RemoteWorkLimiters.create(tenantConfig),
                                        tenantConfig.authorizationCode()
                                                .filter(OidcAuthorizationCodeConfig::enabled)
                                                .map(OidcRefreshCoordinator::new),
                                        webClient);
        }

        private static Optional<String> jwkSetAccessToken(OidcTenantConfig tenant,
                                                           URI jwkSetUri,
                                                           WebClient webClient,
                                                           OidcEndpointClient endpointClient) {
            if (tenant.adapter().isEmpty()) {
                return Optional.empty();
            }
            return tenant.adapter().orElseThrow().jwkSetAccessToken(tenant, jwkSetUri, webClient, scope -> {
                OidcTokenEndpointResult result = endpointClient.clientCredentialsToken(Optional.of(scope), List.of());
                if (!result.succeeded()) {
                    throw new IllegalStateException("JWK Set Client Credentials Grant failed");
                }
                return result.tokenResponse().orElseThrow().accessToken();
            });
        }
    }

    private record RemoteWorkLimiters(OidcRemoteWorkLimiter introspection,
                                      OidcRemoteWorkLimiter clientCredentials,
                                      OidcRemoteWorkLimiter tokenExchange) {
        private static RemoteWorkLimiters create(OidcTenantConfig tenantConfig) {
            OidcRemoteWorkConfig introspectionConfig = tenantConfig.protectedResource()
                    .map(OidcProtectedResourceConfig::tokenValidation)
                    .map(OidcTokenValidationConfig::introspection)
                    .map(OidcIntrospectionConfig::remoteWork)
                    .orElseGet(OidcRemoteWorkConfig::create);
            return new RemoteWorkLimiters(new OidcRemoteWorkLimiter(introspectionConfig),
                                          new OidcRemoteWorkLimiter(tenantConfig.clientCredentialsRemoteWork()),
                                          new OidcRemoteWorkLimiter(tenantConfig.tokenExchangeRemoteWork()));
        }
    }
}
