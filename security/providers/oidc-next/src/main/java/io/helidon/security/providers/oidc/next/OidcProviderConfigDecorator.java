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

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.helidon.builder.api.Prototype;
import io.helidon.config.Config;
import io.helidon.webclient.api.WebClientConfig;

final class OidcProviderConfigDecorator
        implements Prototype.BuilderDecorator<OidcProviderConfig.BuilderBase<?, ?>> {
    static final WebClientConfig DEFAULT_WEBCLIENT = WebClientConfig.create();

    private static final String DEFAULT_SINGLE_TENANT_ID = "default";
    private static final List<String> ROOT_TENANT_CONFIG_KEYS = List.of("enabled",
                                                                        "initialization-retry-interval",
                                                                        "initialization-max-queued",
                                                                        "issuer",
                                                                        "client-id",
                                                                        "client-secret",
                                                                        "token-endpoint-auth-method",
                                                                        "outbound-mutual-tls",
                                                                        "id-token",
                                                                        "client-assertion",
                                                                        "webclient",
                                                                        "jwk-set",
                                                                        "client-credentials-remote-work",
                                                                        "token-exchange-remote-work",
                                                                        "endpoints",
                                                                        "protected-resource",
                                                                        "authorization-code",
                                                                        "endpoint-policy",
                                                                        "logout",
                                                                        "user-info",
                                                                        "token-transport",
                                                                        "subject-mapping",
                                                                        "cookies");
    private static final Duration DEFAULT_INITIALIZATION_RETRY_INTERVAL =
            OidcTenantConfig.builder().initializationRetryInterval();
    private static final int DEFAULT_INITIALIZATION_MAX_QUEUED = OidcTenantConfig.builder().initializationMaxQueued();
    private static final OidcClientAssertionConfig DEFAULT_CLIENT_ASSERTION = OidcClientAssertionConfig.create();
    private static final OidcIdTokenConfig DEFAULT_ID_TOKEN = OidcIdTokenConfig.create();
    private static final OidcJwkSetConfig DEFAULT_JWK_SET = OidcJwkSetConfig.create();
    private static final OidcRemoteWorkConfig DEFAULT_REMOTE_WORK = OidcRemoteWorkConfig.create();
    private static final OidcEndpointConfig DEFAULT_ENDPOINTS = OidcEndpointConfig.create();
    private static final OidcEndpointPolicyConfig DEFAULT_ENDPOINT_POLICY = OidcEndpointPolicyConfig.create();
    private static final OidcTokenTransportConfig DEFAULT_TOKEN_TRANSPORT = OidcTokenTransportConfig.create();
    private static final OidcSubjectMappingConfig DEFAULT_SUBJECT_MAPPING = OidcSubjectMappingConfig.create();
    private static final OidcCookieConfig DEFAULT_COOKIES = OidcCookieConfig.create();

    @Override
    public void decorate(OidcProviderConfig.BuilderBase<?, ?> target) {
        boolean singleTenantConfigured = singleTenantConfigured(target);
        if (singleTenantConfigured) {
            String singleTenantId = target.defaultTenant().orElse(DEFAULT_SINGLE_TENANT_ID);
            OidcTenantConfig singleTenant = singleTenant(target);
            if (target.tenants().isEmpty()) {
                target.putTenant(singleTenantId, singleTenant);
            } else if (target.config().map(config -> config.get("tenants").exists()).orElse(false)
                    || target.tenants().size() != 1
                    || !singleTenant.equals(target.tenants().get(singleTenantId))) {
                throw new IllegalArgumentException("Root tenant configuration cannot be combined with tenants");
            }
        }

        if (target.defaultTenant().isEmpty() && target.tenants().size() == 1) {
            target.defaultTenant(target.tenants().keySet().iterator().next());
        }

        target.defaultTenant().ifPresent(defaultTenant -> {
            if (!target.tenants().containsKey(defaultTenant)) {
                throw new IllegalArgumentException("default-tenant must reference a configured tenant");
            }
        });

        OidcMixUpProtection.validateIssuerBindings(target.tenants());

        Map<String, String> sessionNamespaces = new HashMap<>();
        for (OidcTenantConfig tenant : target.tenants().values()) {
            if (!tenant.enabled()) {
                continue;
            }
            String base = tenant.cookies().localAuthenticationCookieName();
            for (int index = 0; index < OidcCookieStateHandler.MAX_SESSION_COOKIES; index++) {
                String name = OidcCookieStateHandler.sessionCookieName(tenant.cookies(), index);
                String existing = sessionNamespaces.putIfAbsent(name, base);
                if (existing != null && !existing.equals(base)) {
                    throw new IllegalArgumentException("OIDC tenant session cookie namespaces overlap");
                }
            }
        }
        for (OidcTenantConfig tenant : target.tenants().values()) {
            if (!tenant.enabled()) {
                continue;
            }
            if (sessionNamespaces.containsKey(tenant.cookies().authenticationRequestCookieName())
                    || sessionNamespaces.containsKey(
                            OidcCookieStateHandler.browserSessionGenerationCookieName(tenant.cookies()))) {
                throw new IllegalArgumentException("OIDC session cookie namespace overlaps a state or generation cookie");
            }
        }

        if (OidcOutboundPolicy.targetClientCredentialsGrantEnabled(target.outboundTargets())) {
            target.tenants()
                    .values()
                    .stream()
                    .filter(OidcTenantConfig::enabled)
                    .forEach(tenant -> OidcClientAuthenticationConfigValidator.validateClientCredentialsGrant(
                            tenant,
                            tenant.endpoints(),
                            "Client Credentials Grant"));
        }
        if (OidcOutboundPolicy.targetTokenExchangeEnabled(target.outboundTargets())) {
            target.tenants()
                    .values()
                    .stream()
                    .filter(OidcTenantConfig::enabled)
                    .forEach(tenant -> OidcClientAuthenticationConfigValidator.validateTokenExchange(tenant,
                                                                                                      tenant.endpoints()));
        }
    }

    private static boolean singleTenantConfigured(OidcProviderConfig.BuilderBase<?, ?> target) {
        return target.config()
                .filter(OidcProviderConfigDecorator::rootTenantConfigPresent)
                .isPresent()
                || rootTenantOptionsChanged(target)
                || (target.tenants().isEmpty() && !target.outboundTargets().isEmpty());
    }

    private static boolean rootTenantConfigPresent(Config config) {
        return ROOT_TENANT_CONFIG_KEYS.stream()
                .map(config::get)
                .anyMatch(Config::exists);
    }

    private static boolean rootTenantOptionsChanged(OidcProviderConfig.BuilderBase<?, ?> target) {
        return !target.enabled()
                || !DEFAULT_INITIALIZATION_RETRY_INTERVAL.equals(target.initializationRetryInterval())
                || DEFAULT_INITIALIZATION_MAX_QUEUED != target.initializationMaxQueued()
                || target.issuer().isPresent()
                || target.clientId().isPresent()
                || target.clientSecret().isPresent()
                || target.tokenEndpointAuthenticationMethod().isPresent()
                || target.outboundMutualTls()
                || !DEFAULT_ID_TOKEN.equals(target.idToken())
                || !DEFAULT_CLIENT_ASSERTION.equals(target.clientAssertion())
                || target.webClient() != DEFAULT_WEBCLIENT
                || !DEFAULT_JWK_SET.equals(target.jwkSet())
                || !DEFAULT_REMOTE_WORK.equals(target.clientCredentialsRemoteWork())
                || !DEFAULT_REMOTE_WORK.equals(target.tokenExchangeRemoteWork())
                || !DEFAULT_ENDPOINTS.equals(target.endpoints())
                || target.protectedResource().isPresent()
                || target.authorizationCode().isPresent()
                || !DEFAULT_ENDPOINT_POLICY.equals(target.endpointPolicy())
                || target.logout().isPresent()
                || target.userInfo().isPresent()
                || !DEFAULT_TOKEN_TRANSPORT.equals(target.tokenTransport())
                || !DEFAULT_SUBJECT_MAPPING.equals(target.subjectMapping())
                || !DEFAULT_COOKIES.equals(target.cookies());
    }

    private static OidcTenantConfig singleTenant(OidcProviderConfig.BuilderBase<?, ?> target) {
        if (target.webClient() == DEFAULT_WEBCLIENT) {
            // Keep the marker out of tenants and retain a fresh default for repeated builds of this builder.
            target.webClient(WebClientConfig.create());
        }
        OidcTenantConfig.Builder tenant = OidcTenantConfig.builder()
                .enabled(target.enabled())
                .initializationRetryInterval(target.initializationRetryInterval())
                .initializationMaxQueued(target.initializationMaxQueued())
                .outboundMutualTls(target.outboundMutualTls())
                .idToken(target.idToken())
                .clientAssertion(target.clientAssertion())
                .webClient(target.webClient())
                .jwkSet(target.jwkSet())
                .clientCredentialsRemoteWork(target.clientCredentialsRemoteWork())
                .tokenExchangeRemoteWork(target.tokenExchangeRemoteWork())
                .endpoints(target.endpoints())
                .endpointPolicy(target.endpointPolicy())
                .tokenTransport(target.tokenTransport())
                .subjectMapping(target.subjectMapping())
                .cookies(target.cookies());

        target.issuer().ifPresent(tenant::issuer);
        target.clientId().ifPresent(tenant::clientId);
        target.clientSecret().ifPresent(tenant::clientSecret);
        target.tokenEndpointAuthenticationMethod().ifPresent(tenant::tokenEndpointAuthenticationMethod);
        target.protectedResource().ifPresent(tenant::protectedResource);
        target.authorizationCode().ifPresent(tenant::authorizationCode);
        target.logout().ifPresent(tenant::logout);
        target.userInfo().ifPresent(tenant::userInfo);

        return tenant.buildPrototype();
    }
}
