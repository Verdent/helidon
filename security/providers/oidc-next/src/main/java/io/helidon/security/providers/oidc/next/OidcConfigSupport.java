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
import java.time.Duration;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import io.helidon.builder.api.Prototype;
import io.helidon.config.Config;
import io.helidon.common.tls.ConfiguredTlsManager;
import io.helidon.common.tls.TlsConfig;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.webclient.api.Proxy;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;

final class OidcConfigSupport {
    private static final String DEFAULT_SINGLE_TENANT_ID = "default";
    private static final String OFFLINE_ACCESS_SCOPE = "offline_access";
    private static final String PROMPT_NONE = "none";
    private static final String TENANT_VARIABLE = "{tenant}";
    private static final System.Logger LOGGER = System.getLogger(OidcConfigSupport.class.getName());
    static final URI DEFAULT_REDIRECTION_ENDPOINT_URI = URI.create("/oidc/callback");
    private static final List<String> ROOT_TENANT_CONFIG_KEYS = List.of("enabled",
                                                                        "issuer",
                                                                        "client-id",
                                                                        "client-secret",
                                                                        "token-endpoint-auth-method",
                                                                        "id-token",
                                                                        "client-assertion",
                                                                        "webclient",
                                                                        "jwk-set",
                                                                        "endpoints",
                                                                        "protected-resource",
                                                                        "authorization-code",
                                                                        "endpoint-policy",
                                                                        "logout",
                                                                        "user-info",
                                                                        "token-transport",
                                                                        "subject-mapping",
                                                                        "cookies");
    private static final OidcClientAssertionConfig DEFAULT_CLIENT_ASSERTION = OidcClientAssertionConfig.create();
    private static final OidcIdTokenConfig DEFAULT_ID_TOKEN = OidcIdTokenConfig.create();
    private static final WebClientConfig DEFAULT_WEBCLIENT = WebClientConfig.create();
    private static final OidcJwkSetConfig DEFAULT_JWK_SET = OidcJwkSetConfig.create();
    private static final OidcEndpointConfig DEFAULT_ENDPOINTS = OidcEndpointConfig.create();
    private static final OidcEndpointPolicyConfig DEFAULT_ENDPOINT_POLICY = OidcEndpointPolicyConfig.create();
    private static final OidcTokenTransportConfig DEFAULT_TOKEN_TRANSPORT = OidcTokenTransportConfig.create();
    private static final OidcSubjectMappingConfig DEFAULT_SUBJECT_MAPPING = OidcSubjectMappingConfig.create();
    private static final OidcCookieConfig DEFAULT_COOKIES = OidcCookieConfig.create();
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT =
            WebClientConfig.create().socketOptions().readTimeout();

    private OidcConfigSupport() {
    }

    static Optional<OidcEndpointPolicy> endpointPolicy(OidcTenantConfig tenant) {
        return endpointPolicy(tenant, tenant.endpointPolicy());
    }

    static Optional<OidcEndpointPolicy> endpointPolicy(OidcTenantConfig tenant,
                                                       OidcEndpointPolicyConfig endpointPolicy) {
        boolean bearerTokenSupported = bearerTokenSupported(tenant.protectedResource());
        boolean authenticationCookieSupported = authenticationCookieSupported(tenant.authorizationCode());
        EnumSet<OidcEndpointCredential> acceptedCredentials = resolvedAcceptedCredentials(endpointPolicy,
                                                                                          bearerTokenSupported,
                                                                                          authenticationCookieSupported);
        if (acceptedCredentials.isEmpty()) {
            return Optional.empty();
        }
        OidcAuthenticationFailureResponse failureResponse = resolvedFailureResponse(endpointPolicy,
                                                                                    acceptedCredentials);
        validateResolvedEndpointPolicy(acceptedCredentials,
                                       failureResponse,
                                       bearerTokenSupported,
                                       authenticationCookieSupported);
        return Optional.of(OidcEndpointPolicy.create(acceptedCredentials, failureResponse));
    }

    static boolean targetClientCredentialsGrantEnabled(List<OutboundTarget> outboundTargets) {
        return outboundTargets.stream()
                .map(OidcOutboundPolicy::fromTarget)
                .flatMap(Optional::stream)
                .anyMatch(OidcOutboundPolicy::clientCredentialsGrantEnabled);
    }

    static String clientCredentialsScope(List<String> scopes) {
        if (scopes.isEmpty()) {
            return "";
        }
        return OidcScopeSupport.serializeScopes(scopes);
    }

    static WebClient createWebClient(OidcTenantConfig tenantConfig) {
        WebClientConfig configured = tenantConfig.webClient();
        if (configured.readTimeout().isPresent()
                || !WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT.equals(configured.socketOptions().readTimeout())) {
            return WebClient.create(configured);
        }
        return WebClient.create(WebClientConfig.builder()
                                        .from(configured)
                                        .readTimeout(DEFAULT_READ_TIMEOUT)
                                        .buildPrototype());
    }

    static final class ProviderDecorator implements Prototype.BuilderDecorator<OidcProviderConfig.BuilderBase<?, ?>> {
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

            if (targetClientCredentialsGrantEnabled(target.outboundTargets())) {
                target.tenants()
                        .values()
                        .stream()
                        .filter(OidcTenantConfig::enabled)
                        .forEach(tenant -> validateClientCredentialsGrant(tenant,
                                                                          tenant.endpoints(),
                                                                          "Client Credentials Grant"));
            }
        }
    }

    private static boolean singleTenantConfigured(OidcProviderConfig.BuilderBase<?, ?> target) {
        return target.config()
                .filter(OidcConfigSupport::rootTenantConfigPresent)
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
                || target.issuer().isPresent()
                || target.clientId().isPresent()
                || target.clientSecret().isPresent()
                || target.tokenEndpointAuthenticationMethod().isPresent()
                || !DEFAULT_ID_TOKEN.equals(target.idToken())
                || !DEFAULT_CLIENT_ASSERTION.equals(target.clientAssertion())
                || webClientOptionsChanged(target.webClient())
                || !DEFAULT_JWK_SET.equals(target.jwkSet())
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

    private static boolean webClientOptionsChanged(WebClientConfig webClient) {
        return webClient.readTimeout().isPresent()
                || webClient.connectTimeout().isPresent()
                || !WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT.equals(webClient.socketOptions().readTimeout())
                || !DEFAULT_WEBCLIENT.socketOptions().connectTimeout().equals(webClient.socketOptions().connectTimeout())
                || webClient.followRedirects() != DEFAULT_WEBCLIENT.followRedirects()
                || webClient.maxRedirects() != DEFAULT_WEBCLIENT.maxRedirects()
                || webClient.keepAlive() != DEFAULT_WEBCLIENT.keepAlive()
                || proxyOptionsChanged(webClient.proxy())
                || !DEFAULT_WEBCLIENT.tls().equals(webClient.tls())
                || webClient.baseUri().isPresent()
                || webClient.baseAddress().isPresent()
                || !webClient.defaultHeadersMap().isEmpty()
                || !webClient.headers().isEmpty()
                || !webClient.properties().isEmpty()
                || !DEFAULT_WEBCLIENT.protocolConfigs().equals(webClient.protocolConfigs())
                || !webClient.protocolPreference().isEmpty();
    }

    private static boolean proxyOptionsChanged(Proxy proxy) {
        Proxy defaultProxy = DEFAULT_WEBCLIENT.proxy();
        return proxy.type() != defaultProxy.type()
                || proxy.port() != defaultProxy.port()
                || !Optional.ofNullable(defaultProxy.host()).equals(Optional.ofNullable(proxy.host()))
                || !defaultProxy.username().equals(proxy.username())
                || defaultProxy.password().isPresent() != proxy.password().isPresent();
    }

    private static OidcTenantConfig singleTenant(OidcProviderConfig.BuilderBase<?, ?> target) {
        OidcTenantConfig.Builder tenant = OidcTenantConfig.builder()
                .enabled(target.enabled())
                .idToken(target.idToken())
                .clientAssertion(target.clientAssertion())
                .webClient(target.webClient())
                .jwkSet(target.jwkSet())
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

    static final class TenantDecorator implements Prototype.BuilderDecorator<OidcTenantConfig.BuilderBase<?, ?>> {
        @Override
        public void decorate(OidcTenantConfig.BuilderBase<?, ?> target) {
            if (!target.enabled()) {
                return;
            }
            OidcSubjectMappingConfig subjectMapping = target.subjectMapping();
            validateClaimPaths(subjectMapping.principalIdClaimPaths(),
                               "subject-mapping.principal-id-claim-paths",
                               true);
            validateClaimPaths(subjectMapping.principalNameClaimPaths(),
                               "subject-mapping.principal-name-claim-paths",
                               false);
            validateClaimPaths(subjectMapping.roleClaimPaths(), "subject-mapping.role-claim-paths", false);
            validateClaimPaths(subjectMapping.scopeClaimPaths(), "subject-mapping.scope-claim-paths", false);
            validateIdToken(target.idToken());
            validateClientAssertion(target.clientAssertion());
            validateJwkSet(target.jwkSet());
            target.protectedResource()
                    .map(OidcProtectedResourceConfig::tokenValidation)
                    .ifPresent(OidcConfigSupport::validateTokenValidation);
            target.issuer().ifPresent(issuer -> validateIssuerUri(issuer, target.endpoints().tlsRequired()));
            validateAuthorizationCode(target, target.authorizationCode(), target.endpoints());
            validateUserInfo(target, target.userInfo(), target.authorizationCode(), target.endpoints());
            validateLogout(target, target.logout(), target.authorizationCode(), target.endpoints());
            validateProtectedResource(target, target.protectedResource(), target.tokenTransport(), target.endpoints());
            validateEndpointPolicy(target.protectedResource(), target.authorizationCode(), target.endpointPolicy());
        }
    }

    private static void validateJwkSet(OidcJwkSetConfig jwkSet) {
        if (jwkSet.unknownKeyIdRefreshInterval().isNegative()) {
            throw new IllegalArgumentException("jwk-set.unknown-key-id-refresh-interval must not be negative");
        }
        jwkSet.refreshInterval()
                .filter(interval -> interval.isZero() || interval.isNegative())
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException("jwk-set.refresh-interval must be positive");
                });
    }

    private static void validateIdToken(OidcIdTokenConfig idToken) {
        if (idToken.allowedAlgorithms().isEmpty()) {
            throw new IllegalArgumentException("id-token.allowed-algorithms must not be empty");
        }
        if (idToken.allowedEncryptionAlgorithms().isEmpty()) {
            throw new IllegalArgumentException("id-token.allowed-encryption-algorithms must not be empty");
        }
        if (idToken.allowedContentEncryptionAlgorithms().isEmpty()) {
            throw new IllegalArgumentException("id-token.allowed-content-encryption-algorithms must not be empty");
        }
        if (idToken.clockSkew().isNegative()) {
            throw new IllegalArgumentException("id-token.clock-skew must not be negative");
        }
        idToken.trustedAdditionalAudiences()
                .stream()
                .filter(audience -> audience == null
                        || audience.isBlank()
                        || !audience.equals(audience.strip()))
                .findFirst()
                .ifPresent(audience -> {
                    /*
                     * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                     * Quote: "The ID Token MUST be rejected if the ID Token does not list the Client as a valid
                     * audience, or if it contains additional audiences not trusted by the Client."
                     */
                    throw new IllegalArgumentException(
                            "id-token.trusted-additional-audiences must not contain blank or padded values");
                });
        idToken.allowedAlgorithms()
                .stream()
                .filter(algorithm -> algorithm == null
                        || algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip())
                        || "none".equalsIgnoreCase(algorithm))
                .findFirst()
                .ifPresent(algorithm -> {
                    /*
                     * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                     * Quote: "The Client MUST validate the signature of all other ID Tokens according to JWS [JWS]
                     * using the algorithm specified in the JWT `alg` Header Parameter."
                     * Quote: "The Client MUST use the keys provided by the Issuer."
                     */
                    throw new IllegalArgumentException(
                            "id-token.allowed-algorithms must not contain blank, padded, or none values");
                });
        idToken.allowedAlgorithms()
                .stream()
                .filter(algorithm -> algorithm != null && algorithm.toUpperCase(Locale.ROOT).startsWith("HS"))
                .findFirst()
                .ifPresent(algorithm -> {
                    /*
                     * Spec: OpenID Connect Core 1.0, 3.1.3.7 ID Token Validation
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                     * Quote: "If the JWT `alg` Header Parameter uses a MAC based algorithm such as `HS256`, `HS384`,
                     * or `HS512`, the octets of the UTF-8 representation of the `client_secret` corresponding to the
                     * `client_id` contained in the `aud` (audience) Claim are used as the key to validate the
                     * signature."
                     */
                    throw new IllegalArgumentException(
                            "id-token.allowed-algorithms must not contain HS* algorithms");
                });
        idToken.allowedEncryptionAlgorithms()
                .stream()
                .filter(algorithm -> algorithm == null
                        || algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip()))
                .findFirst()
                .ifPresent(algorithm -> {
                    throw new IllegalArgumentException(
                            "id-token.allowed-encryption-algorithms must not contain blank or padded values");
                });
        idToken.allowedContentEncryptionAlgorithms()
                .stream()
                .filter(algorithm -> algorithm == null
                        || algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip()))
                .findFirst()
                .ifPresent(algorithm -> {
                    throw new IllegalArgumentException(
                            "id-token.allowed-content-encryption-algorithms must not contain blank or padded values");
                });
        idToken.allowedEncryptionAlgorithms()
                .stream()
                .filter("RSA1_5"::equals)
                .findFirst()
                .ifPresent(algorithm -> {
                    /*
                     * Spec: RFC 7516, 11.5 Timing Attacks
                     * https://www.rfc-editor.org/rfc/rfc7516.html#section-11.5
                     * Quote: "To mitigate the attacks described in RFC 3218, the recipient MUST NOT distinguish
                     * between format, padding, and length errors of encrypted keys."
                     */
                    LOGGER.log(System.Logger.Level.WARNING,
                               "id-token.allowed-encryption-algorithms contains RSA1_5. This should be used only for "
                                       + "legacy OpenID Providers that cannot use RSA-OAEP or RSA-OAEP-256.");
                });
    }

    private static void validateTokenValidation(OidcTokenValidationConfig tokenValidation) {
        tokenValidation.introspection()
                .clientAssertion()
                .ifPresent(OidcConfigSupport::validateClientAssertion);
        tokenValidation.allowedAlgorithms()
                .stream()
                .filter(algorithm -> algorithm != null && "none".equalsIgnoreCase(algorithm.strip()))
                .findFirst()
                .ifPresent(algorithm -> {
                    /*
                     * Spec: RFC 9068, 2.1 Header and 4 Validation
                     * https://www.rfc-editor.org/rfc/rfc9068.html#section-2.1
                     * https://www.rfc-editor.org/rfc/rfc9068.html#section-4
                     * Quote: "JWT access tokens MUST NOT use \"none\" as the signing algorithm."
                     * Quote: "The resource server MUST reject any JWT in which the value of \"alg\" is \"none\"."
                     */
                    throw new IllegalArgumentException("token-validation.allowed-algorithms must not contain none");
                });
    }

    static final class EndpointPolicyDecorator
            implements Prototype.BuilderDecorator<OidcEndpointPolicyConfig.BuilderBase<?, ?>> {
        @Override
        public void decorate(OidcEndpointPolicyConfig.BuilderBase<?, ?> target) {
            if (target.config()
                    .map(config -> config.get("accepted-credentials").exists())
                    .orElse(false)
                    && target.acceptedCredentials().isEmpty()) {
                throw new IllegalArgumentException("endpoint-policy.accepted-credentials must not be empty when configured");
            }
            Set<OidcEndpointCredential> uniqueCredentials = EnumSet.noneOf(OidcEndpointCredential.class);
            target.acceptedCredentials().forEach(credential -> {
                if (!uniqueCredentials.add(credential)) {
                    throw new IllegalArgumentException(
                            "endpoint-policy.accepted-credentials contains duplicate credential: " + credential);
                }
            });
        }
    }

    static final class OutboundTargetDecorator
            implements Prototype.BuilderDecorator<OidcOutboundTargetConfig.BuilderBase<?, ?>> {
        @Override
        public void decorate(OidcOutboundTargetConfig.BuilderBase<?, ?> target) {
            if (target.tokenPropagationEnabled() && target.clientCredentialsGrantEnabled()) {
                throw new IllegalArgumentException(
                        "Token Propagation and Client Credentials Grant cannot both be enabled on the same outbound target");
            }
            if (!target.clientCredentialsGrantEnabled() && !target.clientCredentialsScopes().isEmpty()) {
                throw new IllegalArgumentException(
                        "client-credentials-grant-enabled must be enabled when client-credentials-scopes is configured");
            }
            if (!target.clientCredentialsGrantEnabled() && !target.clientCredentialsResources().isEmpty()) {
                throw new IllegalArgumentException(
                        "client-credentials-grant-enabled must be enabled when client-credentials-resources is configured");
            }
            target.audience()
                    .filter(audience -> audience.isBlank() || !audience.equals(audience.strip()))
                    .ifPresent(ignored -> {
                        throw new IllegalArgumentException("audience must not be blank or padded");
                    });
            if (target.tokenPropagationEnabled()) {
                if (target.audienceValidationEnabled()) {
                    /*
                     * Spec: RFC 9700, 2.3 Privilege Restriction and 4.10.2 Audience-Restricted Access Tokens
                     * https://www.rfc-editor.org/rfc/rfc9700.html#section-2.3
                     * https://www.rfc-editor.org/rfc/rfc9700.html#section-4.10.2
                     * Quote: "access tokens SHOULD be audience-restricted to a specific resource server or, if that is
                     * not feasible, to a small set of resource servers."
                     * Quote: "The authorization server associates the access token with the particular resource server,
                     * and the resource server is then supposed to verify the intended audience."
                     */
                    target.audience()
                            .orElseThrow(() -> new IllegalArgumentException(
                                    "audience must be configured when Token Propagation audience validation is enabled"));
                } else {
                    LOGGER.log(System.Logger.Level.WARNING,
                               "Token Propagation audience validation is disabled. Propagated bearer tokens will not "
                                       + "be checked locally for the downstream audience and this should be used only "
                                       + "for testing, local development, or legacy opaque-token deployments.");
                }
            }
            OidcScopeSupport.validateConfiguredScopes(target.clientCredentialsScopes(), "client-credentials-scopes");
            validateClientCredentialsResources(target.clientCredentialsResources());
        }

        private void validateClientCredentialsResources(List<String> resources) {
            Set<String> uniqueResources = new LinkedHashSet<>();
            for (String resource : resources) {
                if (resource == null || resource.isBlank() || !resource.equals(resource.strip())) {
                    throw new IllegalArgumentException(
                            "client-credentials-resources must not contain blank or padded values");
                }
                if (!uniqueResources.add(resource)) {
                    throw new IllegalArgumentException(
                            "client-credentials-resources contains duplicate resource: " + resource);
                }
                URI uri;
                try {
                    uri = URI.create(resource);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException(
                            "client-credentials-resources contains an invalid resource URI: " + resource, e);
                }
                if (!uri.isAbsolute()) {
                    throw new IllegalArgumentException(
                            "client-credentials-resources must contain absolute resource URIs");
                }
                if (uri.getRawFragment() != null) {
                    throw new IllegalArgumentException(
                            "client-credentials-resources must not contain URI fragments");
                }
            }
        }
    }

    static final class TenantResolutionDecorator
            implements Prototype.BuilderDecorator<OidcTenantResolutionConfig.BuilderBase<?, ?>> {
        @Override
        public void decorate(OidcTenantResolutionConfig.BuilderBase<?, ?> target) {
            target.headerName()
                    .filter(headerName -> headerName.isBlank() || !headerName.equals(headerName.strip()))
                    .ifPresent(ignored -> {
                        throw new IllegalArgumentException("tenant-resolution.header-name must not be blank or padded");
                    });
            target.pathSegment()
                    .filter(pathSegment -> pathSegment < 0)
                    .ifPresent(ignored -> {
                        throw new IllegalArgumentException("tenant-resolution.path-segment must not be negative");
                    });
            target.pathTemplate().ifPresent(pathTemplate -> {
                if (pathTemplate.isBlank() || !pathTemplate.equals(pathTemplate.strip())) {
                    throw new IllegalArgumentException("tenant-resolution.path-template must not be blank or padded");
                }
                validateSingleTenantVariable(pathTemplate, "tenant-resolution.path-template");
                if (!pathTemplateSegments(pathTemplate).contains(TENANT_VARIABLE)) {
                    throw new IllegalArgumentException(
                            "tenant-resolution.path-template must contain {tenant} as a complete path segment");
                }
            });
            target.hostTemplate().ifPresent(hostTemplate -> {
                if (hostTemplate.isBlank() || !hostTemplate.equals(hostTemplate.strip())) {
                    throw new IllegalArgumentException("tenant-resolution.host-template must not be blank or padded");
                }
                validateSingleTenantVariable(hostTemplate, "tenant-resolution.host-template");
            });
        }
    }

    private static void validateSingleTenantVariable(String template, String configKey) {
        int variableIndex = template.indexOf(TENANT_VARIABLE);
        if (variableIndex == -1
                || template.indexOf(TENANT_VARIABLE, variableIndex + TENANT_VARIABLE.length()) != -1) {
            throw new IllegalArgumentException(configKey + " must contain exactly one {tenant} placeholder");
        }
    }

    private static List<String> pathTemplateSegments(String pathTemplate) {
        return Arrays.stream(pathTemplate.split("/"))
                .filter(segment -> !segment.isEmpty())
                .toList();
    }

    private static void validateClaimPaths(List<String> paths, String configKey, boolean required) {
        if (required && paths.isEmpty()) {
            throw new IllegalArgumentException(configKey + " must not be empty");
        }
        paths.stream()
                .filter(path -> {
                    if (path.isBlank() || !path.equals(path.strip())) {
                        return true;
                    }
                    return Arrays.stream(path.split("\\.", -1))
                            .anyMatch(segment -> segment.isBlank() || !segment.equals(segment.strip()));
                })
                .findFirst()
                .ifPresent(path -> {
                    throw new IllegalArgumentException(configKey + " contains invalid claim path: " + path);
                });
    }

    private static void validateEndpointPolicy(Optional<OidcProtectedResourceConfig> protectedResource,
                                               Optional<OidcAuthorizationCodeConfig> authorizationCode,
                                               OidcEndpointPolicyConfig endpointPolicy) {
        boolean bearerTokenSupported = bearerTokenSupported(protectedResource);
        boolean authenticationCookieSupported = authenticationCookieSupported(authorizationCode);
        EnumSet<OidcEndpointCredential> acceptedCredentials = resolvedAcceptedCredentials(endpointPolicy,
                                                                                          bearerTokenSupported,
                                                                                          authenticationCookieSupported);
        if (acceptedCredentials.isEmpty()) {
            endpointPolicy.authenticationFailureResponse()
                    .ifPresent(ignored -> {
                        throw new IllegalArgumentException(
                                "endpoint-policy requires Protected Resource or Authorization Code Flow to be enabled");
                    });
            return;
        }
        validateResolvedEndpointPolicy(acceptedCredentials,
                                       resolvedFailureResponse(endpointPolicy, acceptedCredentials),
                                       bearerTokenSupported,
                                       authenticationCookieSupported);
    }

    private static boolean bearerTokenSupported(Optional<OidcProtectedResourceConfig> protectedResource) {
        return protectedResource
                .filter(OidcProtectedResourceConfig::enabled)
                .isPresent();
    }

    private static boolean authenticationCookieSupported(Optional<OidcAuthorizationCodeConfig> authorizationCode) {
        return authorizationCode
                .filter(OidcAuthorizationCodeConfig::enabled)
                .isPresent();
    }

    private static EnumSet<OidcEndpointCredential> resolvedAcceptedCredentials(OidcEndpointPolicyConfig endpointPolicy,
                                                                              boolean bearerTokenSupported,
                                                                              boolean authenticationCookieSupported) {
        EnumSet<OidcEndpointCredential> acceptedCredentials = EnumSet.noneOf(OidcEndpointCredential.class);
        if (!endpointPolicy.acceptedCredentials().isEmpty()) {
            acceptedCredentials.addAll(endpointPolicy.acceptedCredentials());
            return acceptedCredentials;
        }
        if (bearerTokenSupported) {
            acceptedCredentials.add(OidcEndpointCredential.BEARER_TOKEN);
        }
        if (authenticationCookieSupported) {
            acceptedCredentials.add(OidcEndpointCredential.AUTHENTICATION_COOKIE);
        }
        return acceptedCredentials;
    }

    private static OidcAuthenticationFailureResponse resolvedFailureResponse(
            OidcEndpointPolicyConfig endpointPolicy,
            Set<OidcEndpointCredential> acceptedCredentials) {
        return endpointPolicy.authenticationFailureResponse()
                .orElseGet(() -> acceptedCredentials.size() == 1
                        && acceptedCredentials.contains(OidcEndpointCredential.AUTHENTICATION_COOKIE)
                        ? OidcAuthenticationFailureResponse.AUTHORIZATION_CODE_REDIRECT
                        : OidcAuthenticationFailureResponse.UNAUTHORIZED);
    }

    private static void validateResolvedEndpointPolicy(Set<OidcEndpointCredential> acceptedCredentials,
                                                       OidcAuthenticationFailureResponse failureResponse,
                                                       boolean bearerTokenSupported,
                                                       boolean authenticationCookieSupported) {
        if (acceptedCredentials.contains(OidcEndpointCredential.BEARER_TOKEN) && !bearerTokenSupported) {
            throw new IllegalArgumentException(
                    "endpoint-policy.accepted-credentials bearer-token requires protected-resource to be enabled");
        }
        if (acceptedCredentials.contains(OidcEndpointCredential.AUTHENTICATION_COOKIE)
                && !authenticationCookieSupported) {
            throw new IllegalArgumentException(
                    "endpoint-policy.accepted-credentials authentication-cookie requires authorization-code to be enabled");
        }
        if (failureResponse == OidcAuthenticationFailureResponse.AUTHORIZATION_CODE_REDIRECT) {
            if (!authenticationCookieSupported) {
                throw new IllegalArgumentException(
                        "endpoint-policy.authentication-failure-response authorization-code-redirect requires "
                                + "authorization-code to be enabled");
            }
            if (!acceptedCredentials.contains(OidcEndpointCredential.AUTHENTICATION_COOKIE)) {
                throw new IllegalArgumentException(
                        "endpoint-policy.authentication-failure-response authorization-code-redirect requires "
                                + "accepted-credentials to include authentication-cookie");
            }
        }
    }

    private static void validateAuthorizationCode(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                  Optional<OidcAuthorizationCodeConfig> configuredAuthorizationCode,
                                                  OidcEndpointConfig endpoints) {
        if (configuredAuthorizationCode.isEmpty()) {
            return;
        }
        OidcAuthorizationCodeConfig authorizationCode = configuredAuthorizationCode.orElseThrow();
        if (!authorizationCode.enabled()) {
            return;
        }

        /*
         * Spec: OpenID Connect Core 1.0, 3.1.2.1 Authentication Request
         * https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
         * Quote: "OpenID Connect requests MUST contain the `openid` scope value."
         * Quote: "`client_id` REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server."
         * Quote: "`redirect_uri` REQUIRED. Redirection URI to which the response will be sent."
         */
        tenant.clientId()
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-id must be configured when Authorization Code Flow is enabled"));
        validateTokenEndpointAuthentication(tenant, false, "Authorization Code Flow");
        validatePkce(tenant, authorizationCode);
        boolean tokenEndpointTlsRequired = endpoints.tlsRequired()
                || mutualTlsTokenEndpointAuthentication(tenant.clientSecret(),
                                                        tenant.tokenEndpointAuthenticationMethod());
        validateRedirectionEndpointUri(redirectionEndpointUri(authorizationCode), endpoints.tlsRequired());
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        requireEndpointOrWellKnown(endpoints.authorizationEndpointUri(),
                                   wellKnownUri,
                                   "authorization-endpoint-uri",
                                   "Authorization Code Flow",
                                   endpoints.tlsRequired(),
                                   OidcConfigSupport::validateAuthorizationEndpointUri);
        requireEndpointOrWellKnown(endpoints.tokenEndpointUri(),
                                   wellKnownUri,
                                   "token-endpoint-uri",
                                   "Authorization Code Flow",
                                   tokenEndpointTlsRequired,
                                   tokenEndpointTlsRequired,
                                   OidcConfigSupport::validateTokenEndpointUri);
        if (tenant.issuer().isEmpty() && endpoints.wellKnownUri().isEmpty()) {
            throw new IllegalArgumentException(
                    "issuer or well-known-uri must be configured when Authorization Code Flow is enabled");
        }
        OidcScopeSupport.validateConfiguredScopes(authorizationCode.scopes(), "authorization-code.scopes");
        if (!authorizationCode.scopes().contains("openid")) {
            throw new IllegalArgumentException(
                    "openid scope must be configured when Authorization Code Flow is enabled");
        }
        validateAuthorizationCodePrompts(authorizationCode.scopes(), authorizationCode.prompts());
        tenant.cookies()
                .encryptionSecret()
                .orElseThrow(() -> new IllegalArgumentException(
                        "cookies.encryption-secret must be configured when Authorization Code Flow is enabled"));
    }

    private static void validateAuthorizationCodePrompts(List<String> scopes, List<String> prompts) {
        /*
         * Spec: OpenID Connect Core 1.0, 3.1.2.1 Authentication Request
         * https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
         * Quote: "`prompt` OPTIONAL. Space-delimited, case-sensitive list of ASCII string values".
         * Quote: "If this parameter contains `none` with any other value, an error is returned."
         */
        Set<String> seen = new LinkedHashSet<>();
        for (String prompt : prompts) {
            if (prompt == null
                    || prompt.isBlank()
                    || !prompt.equals(prompt.strip())
                    || prompt.codePoints().anyMatch(codePoint -> codePoint <= 0x20 || codePoint > 0x7E)) {
                throw new IllegalArgumentException(
                        "authorization-code.prompts must contain visible ASCII values without whitespace");
            }
            if (!seen.add(prompt)) {
                throw new IllegalArgumentException(
                        "authorization-code.prompts contains duplicate prompt: " + prompt);
            }
        }
        if (prompts.size() > 1 && prompts.contains(PROMPT_NONE)) {
            throw new IllegalArgumentException(
                    "authorization-code.prompts cannot combine none with other prompt values");
        }
        if (scopes.contains(OFFLINE_ACCESS_SCOPE) && prompts.contains(PROMPT_NONE)) {
            /*
             * Spec: OpenID Connect Core 1.0, 11 Offline Access
             * https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
             * Quote: "When offline access is requested, a `prompt` parameter value of `consent` MUST be used".
             * Quote: "If this parameter contains `none` with any other value, an error is returned."
             */
            throw new IllegalArgumentException(
                    "authorization-code.prompts cannot contain none when authorization-code.scopes contains offline_access");
        }
    }

    private static void validatePkce(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                     OidcAuthorizationCodeConfig authorizationCode) {
        OidcClientAuthenticationMethod method = tokenEndpointAuthenticationMethod(tenant.clientSecret(),
                                                                                  tenant.tokenEndpointAuthenticationMethod());
        if (method != OidcClientAuthenticationMethod.NONE) {
            return;
        }

        /*
         * Spec: RFC 9700, 2.1.1 Authorization Code Grant
         * https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1
         * Quote: "When using PKCE, clients SHOULD use PKCE code challenge methods that do not expose the PKCE verifier
         * in the authorization request."
         *
         * Spec: RFC 7636, 4.2 Client Creates the Code Challenge
         * https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
         * Quote: "If the client is capable of using \"S256\", it MUST use \"S256\", as \"S256\" is Mandatory
         * To Implement (MTI) on the server."
         */
        if (!authorizationCode.pkceRequired()) {
            throw new IllegalArgumentException(
                    "authorization-code.pkce-required cannot be false when Token Endpoint authentication is NONE");
        }
        if (authorizationCode.pkceMethod() == OidcPkceMethod.PLAIN) {
            throw new IllegalArgumentException(
                    "authorization-code.pkce-method must be S256 when Token Endpoint authentication is NONE");
        }
    }

    private static void validateUserInfo(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                         Optional<OidcUserInfoConfig> configuredUserInfo,
                                         Optional<OidcAuthorizationCodeConfig> configuredAuthorizationCode,
                                         OidcEndpointConfig endpoints) {
        if (configuredUserInfo.isEmpty()) {
            return;
        }
        OidcUserInfoConfig userInfo = configuredUserInfo.orElseThrow();
        if (!userInfo.enabled()) {
            return;
        }
        validateClaimPaths(userInfo.attributeClaimPaths(), "user-info.attribute-claim-paths", false);

        configuredAuthorizationCode
                .filter(OidcAuthorizationCodeConfig::enabled)
                .orElseThrow(() -> new IllegalArgumentException(
                        "authorization-code must be configured when UserInfo is enabled"));
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        requireEndpointOrWellKnown(endpoints.userInfoEndpointUri(),
                                   wellKnownUri,
                                   "user-info-endpoint-uri",
                                   "UserInfo",
                                   endpoints.tlsRequired(),
                                   OidcConfigSupport::validateUserInfoEndpointUri);
    }

    private static void validateLogout(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                       Optional<OidcLogoutConfig> configuredLogout,
                                       Optional<OidcAuthorizationCodeConfig> configuredAuthorizationCode,
                                       OidcEndpointConfig endpoints) {
        if (configuredLogout.isEmpty()) {
            return;
        }
        OidcLogoutConfig logout = configuredLogout.orElseThrow();
        if (!logout.enabled()) {
            return;
        }
        validateLocalEndpointUri("local-endpoint-uri", logout.localEndpointUri());
        configuredAuthorizationCode
                .filter(OidcAuthorizationCodeConfig::enabled)
                .map(OidcConfigSupport::redirectionEndpointUri)
                .map(OidcUri::path)
                .filter(logout.localEndpointUri().getPath()::equals)
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException(
                            "local-endpoint-uri must not use the same path as redirection-endpoint-uri");
                });
        validateEndSession(tenant,
                           configuredAuthorizationCode,
                           logout.endSession()
                                   .filter(OidcEndSessionConfig::enabled),
                           endpoints);
    }

    private static void validateEndSession(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                           Optional<OidcAuthorizationCodeConfig> configuredAuthorizationCode,
                                           Optional<OidcEndSessionConfig> configuredEndSession,
                                           OidcEndpointConfig endpoints) {
        if (configuredEndSession.isEmpty()) {
            return;
        }
        OidcEndSessionConfig endSession = configuredEndSession.orElseThrow();
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        requireEndpointOrWellKnown(endpoints.endSessionEndpointUri(),
                                   wellKnownUri,
                                   "end-session-endpoint-uri",
                                   "RP-Initiated Logout",
                                   endpoints.tlsRequired(),
                                   OidcConfigSupport::validateEndSessionEndpointUri);
        endSession.postLogoutRedirectUri()
                .ifPresent(uri -> validatePostLogoutRedirectUri("post-logout-redirect-uri",
                                                                uri,
                                                                endpoints.tlsRequired()));
        endSession.allowedPostLogoutRedirectUris()
                .forEach(uri -> validatePostLogoutRedirectUri("allowed-post-logout-redirect-uris",
                                                              uri,
                                                              endpoints.tlsRequired()));
        if (endSession.idTokenHintRequired()) {
            configuredAuthorizationCode
                    .filter(OidcAuthorizationCodeConfig::enabled)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "authorization-code must be configured when RP-Initiated Logout requires id_token_hint"));
        } else {
            tenant.clientId()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "client-id must be configured when RP-Initiated Logout can omit id_token_hint"));
        }
    }

    private static void validateProtectedResource(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                  Optional<OidcProtectedResourceConfig> configuredProtectedResource,
                                                  OidcTokenTransportConfig tokenTransport,
                                                  OidcEndpointConfig endpoints) {
        if (configuredProtectedResource.isEmpty()) {
            return;
        }
        OidcProtectedResourceConfig protectedResource = configuredProtectedResource.orElseThrow();
        OidcTokenValidationConfig tokenValidation = protectedResource.tokenValidation();
        validateBearerChallengeRealm(protectedResource.challengeRealm());
        if (!protectedResource.enabled() && tokenValidation.method().isEmpty()) {
            return;
        }

        if (protectedResource.enabled()
                && !tokenTransport.authorizationHeaderEnabled()
                && !tokenTransport.queryParameterEnabled()) {
            throw new IllegalArgumentException(
                    "at least one Bearer Token transport must be enabled when Protected Resource is enabled");
        }
        OidcTokenValidationMethod method = tokenValidation.method()
                .orElseThrow(() -> new IllegalArgumentException(
                        "token-validation.method must be configured when Protected Resource is enabled"));

        switch (method) {
        case JWT -> {
            if (tenant.issuer().isEmpty() && endpoints.wellKnownUri().isEmpty()) {
                throw new IllegalArgumentException(
                        "issuer or well-known-uri must be configured when JWT access-token validation is enabled");
            }
            Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
            requireEndpointOrWellKnown(endpoints.jwksUri(),
                                       wellKnownUri,
                                       "jwks-uri",
                                       "JWT access-token validation",
                                       endpoints.tlsRequired(),
                                       OidcConfigSupport::validateJwksUri);
            if (tokenValidation.audienceValidationEnabled()) {
                /*
                 * Spec: RFC 9068, 2.2 Data Structure and 4 Validation
                 * https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2
                 * https://www.rfc-editor.org/rfc/rfc9068.html#section-4
                 * Quote: "`aud` REQUIRED - as defined in Section 4.1.3 of [RFC7519]. See Section 3 for indications on
                 * how an authorization server should determine the value of `aud` depending on the request."
                 * Quote: "The resource server MUST validate that the `aud` claim contains a resource indicator value
                 * corresponding to an identifier the resource server expects for itself."
                 */
                tokenValidation.audience()
                        .orElseThrow(() -> new IllegalArgumentException(
                                "token-validation.audience must be configured when JWT access-token audience validation "
                                        + "is enabled"));
            } else {
                LOGGER.log(System.Logger.Level.WARNING,
                           "JWT access-token audience validation is disabled. This relaxes RFC 9068 validation and "
                                   + "should be used only for testing, local development, or legacy non-RFC9068 tokens.");
            }
        }
        case INTROSPECTION -> {
            /*
             * Spec: RFC 7662, 2.1 Introspection Request
             * https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1
             * Quote: "To prevent token scanning attacks, the endpoint MUST also require some form of authorization to
             * access this endpoint, such as client authentication as described in OAuth 2.0 [RFC6749] or a separate
             * OAuth 2.0 access token such as the bearer token described in OAuth 2.0 Bearer Token Usage [RFC6750]."
             */
            Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
            boolean introspectionEndpointTlsRequired = endpoints.tlsRequired()
                    || mutualTlsIntrospectionEndpointAuthentication(tokenValidation);
            requireEndpointOrWellKnown(endpoints.introspectionEndpointUri(),
                                       wellKnownUri,
                                       "introspection-endpoint-uri",
                                       "introspection",
                                       introspectionEndpointTlsRequired,
                                       OidcConfigSupport::validateIntrospectionEndpointUri);
            validateIntrospectionEndpointAuthentication(tenant, tokenValidation);
            if (tokenValidation.audienceValidationEnabled()) {
                tokenValidation.audience()
                        .orElseThrow(() -> new IllegalArgumentException(
                                "token-validation.audience must be configured when introspection is enabled"));
            }
        }
        default -> throw new IllegalStateException("Unexpected token validation method: " + method);
        }
    }

    static URI redirectionEndpointUri(OidcAuthorizationCodeConfig authorizationCode) {
        return authorizationCode.redirectionEndpointUri()
                .orElse(DEFAULT_REDIRECTION_ENDPOINT_URI);
    }

    static void validateClientCredentialsGrant(OidcTenantConfig tenant,
                                               OidcEndpointConfig endpoints,
                                               String operation) {
        validateClientCredentialsGrant(tenant.clientId(),
                                       tenant.clientSecret(),
                                       tenant.tokenEndpointAuthenticationMethod(),
                                       tenant.clientAssertion(),
                                       tenant.webClient(),
                                       tenant.issuer(),
                                       endpoints,
                                       operation);
    }

    static boolean tokenEndpointTlsRequired(OidcTenantConfig tenant) {
        return tenant.endpoints().tlsRequired()
                || mutualTlsTokenEndpointAuthentication(tenant.clientSecret(), tenant.tokenEndpointAuthenticationMethod());
    }

    private static void validateClientCredentialsGrant(Optional<String> clientId,
                                                       Optional<String> clientSecret,
                                                       Optional<OidcClientAuthenticationMethod> authenticationMethod,
                                                       OidcClientAssertionConfig clientAssertion,
                                                       WebClientConfig webClient,
                                                       Optional<String> issuer,
                                                       OidcEndpointConfig endpoints,
                                                       String operation) {
        /*
         * Spec: RFC 6749, 4.4 Client Credentials Grant and 4.4.2 Access Token Request
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.2
         * RFC 6749 section 4.4 quote: "The client credentials grant type MUST only be used by confidential clients."
         * RFC 6749 section 4.4.2 quote: "The authorization server MUST authenticate the client."
         */
        clientId.orElseThrow(() -> new IllegalArgumentException(
                "client-id must be configured when " + operation + " is enabled"));
        validateTokenEndpointAuthentication(clientSecret,
                                            authenticationMethod,
                                            clientAssertion,
                                            webClient,
                                            true,
                                            operation);
        boolean tokenEndpointTlsRequired = endpoints.tlsRequired()
                || mutualTlsTokenEndpointAuthentication(clientSecret, authenticationMethod);
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(issuer, endpoints);
        requireEndpointOrWellKnown(endpoints.tokenEndpointUri(),
                                   wellKnownUri,
                                   "token-endpoint-uri",
                                   operation,
                                   tokenEndpointTlsRequired,
                                   tokenEndpointTlsRequired,
                                   OidcConfigSupport::validateTokenEndpointUri);
    }

    private static void requireEndpointOrWellKnown(Optional<URI> endpointUri,
                                                   Optional<URI> wellKnownUri,
                                                   String endpointConfigKey,
                                                   String operation,
                                                   boolean tlsRequired,
                                                   EndpointUriValidator endpointValidator) {
        requireEndpointOrWellKnown(endpointUri,
                                   wellKnownUri,
                                   endpointConfigKey,
                                   operation,
                                   tlsRequired,
                                   tlsRequired,
                                   endpointValidator);
    }

    private static void requireEndpointOrWellKnown(Optional<URI> endpointUri,
                                                   Optional<URI> wellKnownUri,
                                                   String endpointConfigKey,
                                                   String operation,
                                                   boolean endpointTlsRequired,
                                                   boolean wellKnownTlsRequired,
                                                   EndpointUriValidator endpointValidator) {
        endpointUri
                .or(() -> wellKnownUri)
                .orElseThrow(() -> new IllegalArgumentException(
                        endpointConfigKey + " or well-known-uri must be configured when " + operation + " is enabled"));
        endpointUri.ifPresent(uri -> endpointValidator.validate(uri, endpointTlsRequired));
        if (endpointUri.isEmpty()) {
            wellKnownUri.ifPresent(uri -> validateWellKnownUri(uri, wellKnownTlsRequired));
        }
    }

    static void validateAuthorizationEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components."
         *
         * Spec: RFC 6749, 3.1 Authorization Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
         * Quote: "The endpoint URI MUST NOT include a fragment component".
         */
        validateHttpsEndpointUri("authorization-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("authorization-endpoint-uri", uri);
    }

    static void validateIssuerUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "`issuer` REQUIRED. URL using the `https` scheme with no query or fragment components that the OP
         * asserts as its Issuer Identifier."
         */
        validateHttpsEndpointUri("issuer", uri, tlsRequired, false);
        validateNoQuery("issuer", uri);
        validateNoFragment("issuer", uri);
    }

    static void validateIssuerUri(String issuer, boolean tlsRequired) {
        validateIssuerUri(URI.create(issuer), tlsRequired);
    }

    private static void validateRedirectionEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 6749, 3.1.2 Redirection Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1.2
         * Quote: "The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3."
         * Quote: "The endpoint URI MUST NOT include a fragment component."
         *
         * A local absolute path is accepted as Helidon shorthand. It is resolved to an absolute URI from the incoming
         * request origin before it is sent as the Authentication Request `redirect_uri`.
         */
        if (uri.isAbsolute()) {
            validateHttpsEndpointUri("redirection-endpoint-uri", uri, tlsRequired, false);
            validateNoFragment("redirection-endpoint-uri", uri);
            return;
        }
        if (uri.getRawAuthority() != null) {
            throw new IllegalArgumentException("redirection-endpoint-uri must be an absolute URI or local absolute path: "
                                                       + uri);
        }
        String path = uri.getPath();
        if (path == null || path.isEmpty() || !path.startsWith("/")) {
            throw new IllegalArgumentException("redirection-endpoint-uri must be an absolute URI or local absolute path: "
                                                       + uri);
        }
        validateNoFragment("redirection-endpoint-uri", uri);
    }

    static void validateJwksUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "`jwks_uri` REQUIRED. URL of the OP's JWK Set [JWK] document, which MUST use the `https` scheme."
         */
        validateHttpsEndpointUri("jwks-uri", uri, tlsRequired, true);
    }

    static void validateEndSessionEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect RP-Initiated Logout 1.0, 2.1 OpenID Provider Discovery Metadata
         * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
         * Quote: "`end_session_endpoint` REQUIRED. URL at the OP to which an RP can perform a redirect to request that
         * the End-User be logged out at the OP."
         * Quote: "This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components."
         */
        validateHttpsEndpointUri("end-session-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("end-session-endpoint-uri", uri);
    }

    static void validateUserInfoEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components."
         */
        validateHttpsEndpointUri("user-info-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("user-info-endpoint-uri", uri);
    }

    private static void validatePostLogoutRedirectUri(String configKey, URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect RP-Initiated Logout 1.0, 2 RP-Initiated Logout
         * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
         * Quote: "The `post_logout_redirect_uri` value MUST have been previously registered with the OP, either using
         * the `post_logout_redirect_uris` Registration parameter or via another mechanism."
         * Quote: "This URI SHOULD use the `https` scheme and MAY contain port, path, and query parameter components."
         */
        validateHttpsEndpointUri(configKey, uri, tlsRequired, false);
        validateNoFragment(configKey, uri);
    }

    private static void validateWellKnownUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 4 Obtaining OpenID Provider Configuration Information
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
         * Quote: "OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by
         * concatenating the string `/.well-known/openid-configuration` to the Issuer."
         */
        validateHttpsEndpointUri("well-known-uri", uri, tlsRequired, false);
    }

    static void validateTokenEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 6749, 3.2 Token Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
         * Quote: "The endpoint URI MUST NOT include a fragment component."
         * Quote: "The authorization server MUST require the use of TLS as described in Section 1.6 when sending
         * requests to the token endpoint."
         */
        validateHttpsEndpointUri("token-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("token-endpoint-uri", uri);
    }

    static void validateIntrospectionEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 7662, 2 Introspection Endpoint
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-2
         * Quote: "The introspection endpoint MUST be protected by a transport-layer security mechanism as described in
         * Section 4."
         */
        validateHttpsEndpointUri("introspection-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("introspection-endpoint-uri", uri);
    }

    private static void validateBearerChallengeRealm(String realm) {
        if (realm == null || realm.isBlank() || !OidcOAuthErrorFields.validErrorDescription(realm)) {
            throw new IllegalArgumentException("protected-resource.challenge-realm must contain only RFC 6750 "
                                                       + "challenge value characters");
        }
    }

    private static void validateHttpsEndpointUri(String configKey, URI uri, boolean tlsRequired, boolean fileAllowed) {
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException(configKey + " must define a URI scheme");
        }
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        if (!tlsRequired && ("http".equalsIgnoreCase(scheme) || fileAllowed && "file".equalsIgnoreCase(scheme))) {
            return;
        }
        throw new IllegalArgumentException(
                configKey + " must use https unless endpoints.tls-required is disabled: " + uri);
    }

    private static void validateNoFragment(String configKey, URI uri) {
        if (uri.getRawFragment() != null) {
            throw new IllegalArgumentException(configKey + " must not include a fragment component: " + uri);
        }
    }

    private static void validateNoQuery(String configKey, URI uri) {
        if (uri.getRawQuery() != null) {
            throw new IllegalArgumentException(configKey + " must not include a query component: " + uri);
        }
    }

    private static void validateLocalEndpointUri(String configKey, URI uri) {
        if (uri.getScheme() != null || uri.getRawAuthority() != null) {
            throw new IllegalArgumentException(configKey + " must be a local absolute path: " + uri);
        }
        String path = uri.getPath();
        if (path == null || path.isEmpty() || !path.startsWith("/")) {
            throw new IllegalArgumentException(configKey + " must be a local absolute path: " + uri);
        }
        if (uri.getRawQuery() != null) {
            throw new IllegalArgumentException(configKey + " must not include a query component: " + uri);
        }
        validateNoFragment(configKey, uri);
    }

    private static void validateTokenEndpointAuthentication(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                            boolean confidentialClientRequired,
                                                            String operation) {
        validateTokenEndpointAuthentication(tenant.clientSecret(),
                                            tenant.tokenEndpointAuthenticationMethod(),
                                            tenant.clientAssertion(),
                                            tenant.webClient(),
                                            confidentialClientRequired,
                                            operation);
    }

    private static void validateIntrospectionEndpointAuthentication(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                                    OidcTokenValidationConfig tokenValidation) {
        /*
         * Spec: RFC 7662, 4 Security Considerations
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-4
         * Quote: "To prevent this, the authorization server MUST require authentication of protected resources that
         * need to access the introspection endpoint and SHOULD require protected resources to be specifically
         * authorized to call the introspection endpoint."
         * Quote: "A single piece of software acting as both a client and a protected resource MAY reuse the same
         * credentials between the token endpoint and the introspection endpoint, though doing so potentially conflates
         * the activities of the client and protected resource portions of the software and the authorization server MAY
         * require separate credentials for each mode."
         */
        OidcIntrospectionConfig introspection = tokenValidation.introspection();
        Optional<String> clientSecret = introspection.clientSecret().or(tenant::clientSecret);
        OidcClientAssertionConfig clientAssertion = introspection.clientAssertion()
                .orElseGet(tenant::clientAssertion);
        OidcClientAuthenticationMethod method =
                introspectionEndpointAuthenticationMethod(tenant.clientSecret(), introspection);
        introspection.clientId()
                .or(tenant::clientId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-id must be configured when introspection is enabled"));
        switch (method) {
        case CLIENT_SECRET_BASIC, CLIENT_SECRET_POST -> clientSecret
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-secret must be configured for " + method
                                + " Introspection Endpoint authentication when introspection is enabled"));
        case CLIENT_SECRET_JWT -> {
            clientSecret.orElseThrow(() -> new IllegalArgumentException(
                    "client-secret must be configured for CLIENT_SECRET_JWT Introspection Endpoint authentication when "
                            + "introspection is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.CLIENT_SECRET_JWT,
                                             "Introspection Endpoint",
                                             "introspection");
        }
        case PRIVATE_KEY_JWT -> {
            clientAssertion.jwk()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "client-assertion.jwk must be configured for PRIVATE_KEY_JWT Introspection Endpoint "
                                    + "authentication when introspection is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                             "Introspection Endpoint",
                                             "introspection");
        }
        case TLS_CLIENT_AUTH, SELF_SIGNED_TLS_CLIENT_AUTH -> {
            validateMutualTlsClientAuthentication(tenant.webClient(),
                                                  method,
                                                  "Introspection Endpoint",
                                                  "introspection");
        }
        case NONE -> throw new IllegalArgumentException(
                "Introspection Endpoint authentication cannot be NONE when introspection is enabled");
        default -> throw new IllegalStateException("Unexpected client authentication method: " + method);
        }
    }

    private static void validateTokenEndpointAuthentication(Optional<String> clientSecret,
                                                            Optional<OidcClientAuthenticationMethod> authenticationMethod,
                                                            OidcClientAssertionConfig clientAssertion,
                                                            WebClientConfig webClient,
                                                            boolean confidentialClientRequired,
                                                            String operation) {
        OidcClientAuthenticationMethod method = tokenEndpointAuthenticationMethod(clientSecret, authenticationMethod);
        switch (method) {
        case CLIENT_SECRET_BASIC, CLIENT_SECRET_POST -> clientSecret
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-secret must be configured for " + method
                                + " Token Endpoint authentication when " + operation + " is enabled"));
        case CLIENT_SECRET_JWT -> {
            clientSecret.orElseThrow(() -> new IllegalArgumentException(
                    "client-secret must be configured for CLIENT_SECRET_JWT Token Endpoint authentication when "
                            + operation + " is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.CLIENT_SECRET_JWT,
                                             "Token Endpoint",
                                             operation);
        }
        case PRIVATE_KEY_JWT -> {
            clientAssertion.jwk()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "client-assertion.jwk must be configured for PRIVATE_KEY_JWT Token Endpoint authentication "
                                    + "when " + operation + " is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                             "Token Endpoint",
                                             operation);
        }
        case TLS_CLIENT_AUTH, SELF_SIGNED_TLS_CLIENT_AUTH -> {
            validateMutualTlsClientAuthentication(webClient, method, "Token Endpoint", operation);
        }
        case NONE -> {
            if (confidentialClientRequired) {
                throw new IllegalArgumentException(
                        "Token Endpoint authentication cannot be NONE when " + operation + " is enabled");
            }
        }
        default -> throw new IllegalStateException("Unexpected client authentication method: " + method);
        }
    }

    private static void validateMutualTlsClientAuthentication(WebClientConfig webClient,
                                                              OidcClientAuthenticationMethod method,
                                                              String endpointName,
                                                              String operation) {
        TlsConfig tls = webClient.tls().prototype();
        /*
         * Spec: RFC 8705, 2 Mutual TLS for OAuth Client Authentication
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-2
         * Quote: "In order to utilize TLS for OAuth client authentication, the TLS connection between the client and the
         * authorization server MUST have been established or re-established with mutual-TLS X.509 certificate
         * authentication (i.e., the client Certificate and CertificateVerify messages are sent during the TLS
         * handshake)."
         */
        if (tls.enabled()
                && (tls.sslContext().isPresent()
                        || tls.privateKey().isPresent() && !tls.privateKeyCertChain().isEmpty()
                        || !(tls.manager() instanceof ConfiguredTlsManager))) {
            return;
        }
        throw new IllegalArgumentException(
                "webclient.tls must be enabled and private-key plus certificate chain, ssl-context, or custom manager "
                        + "must be configured for " + method + " " + endpointName + " authentication when " + operation
                        + " is enabled");
    }

    private static boolean mutualTlsTokenEndpointAuthentication(Optional<String> clientSecret,
                                                               Optional<OidcClientAuthenticationMethod> authenticationMethod) {
        OidcClientAuthenticationMethod method = tokenEndpointAuthenticationMethod(clientSecret, authenticationMethod);
        return method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
    }

    private static boolean mutualTlsIntrospectionEndpointAuthentication(OidcTokenValidationConfig tokenValidation) {
        OidcClientAuthenticationMethod method = introspectionEndpointAuthenticationMethod(Optional.empty(),
                                                                                          tokenValidation.introspection());
        return method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
    }

    private static OidcClientAuthenticationMethod tokenEndpointAuthenticationMethod(
            Optional<String> clientSecret,
            Optional<OidcClientAuthenticationMethod> authenticationMethod) {
        return authenticationMethod
                .orElseGet(() -> clientSecret
                        .isPresent()
                        ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        : OidcClientAuthenticationMethod.NONE);
    }

    private static OidcClientAuthenticationMethod introspectionEndpointAuthenticationMethod(
            Optional<String> tenantClientSecret,
            OidcIntrospectionConfig introspection) {
        return introspection.authenticationMethod()
                .orElseGet(() -> introspection.clientSecret()
                        .or(() -> tenantClientSecret)
                        .isPresent()
                        ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        : OidcClientAuthenticationMethod.NONE);
    }

    private static void validateClientAssertion(OidcClientAssertionConfig clientAssertion) {
        if (clientAssertion.lifetime().isZero() || clientAssertion.lifetime().isNegative()) {
            throw new IllegalArgumentException("client-assertion.lifetime must be positive");
        }
        clientAssertion.algorithm()
                .filter(algorithm -> algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip())
                        || "none".equalsIgnoreCase(algorithm))
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException(
                            "client-assertion.algorithm must not be blank, padded, or none");
                });
        clientAssertion.keyId()
                .filter(keyId -> keyId.isBlank() || !keyId.equals(keyId.strip()))
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException("client-assertion.key-id must not be blank or padded");
                });
    }

    private static void validateClientAssertionAlgorithm(OidcClientAssertionConfig clientAssertion,
                                                         OidcClientAuthenticationMethod method,
                                                         String endpointName,
                                                         String operation) {
        clientAssertion.algorithm()
                .filter(algorithm -> switch (method) {
                case CLIENT_SECRET_JWT -> !OidcClientAuthenticationSupport.isClientSecretJwtAlgorithm(algorithm);
                case PRIVATE_KEY_JWT -> !OidcClientAuthenticationSupport.isPrivateKeyJwtAlgorithm(algorithm);
                default -> false;
                })
                .ifPresent(algorithm -> {
                    String algorithms = switch (method) {
                    case CLIENT_SECRET_JWT -> OidcClientAuthenticationSupport.clientSecretJwtAlgorithms();
                    case PRIVATE_KEY_JWT -> OidcClientAuthenticationSupport.privateKeyJwtAlgorithms();
                    default -> throw new IllegalStateException(
                            "Unexpected client assertion authentication method: " + method);
                    };
                    throw new IllegalArgumentException("client-assertion.algorithm must be one of "
                                                               + algorithms
                                                               + " for " + method + " " + endpointName
                                                               + " authentication when "
                                                               + operation + " is enabled");
                });
    }

    @FunctionalInterface
    private interface EndpointUriValidator {
        void validate(URI uri, boolean tlsRequired);
    }
}
