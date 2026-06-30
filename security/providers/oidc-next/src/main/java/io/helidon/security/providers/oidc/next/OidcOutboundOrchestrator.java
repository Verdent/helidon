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

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import io.helidon.http.HeaderNames;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonValueType;
import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.providers.common.OutboundConfig;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.common.TokenCredential;

final class OidcOutboundOrchestrator {
    private static final System.Logger LOGGER = System.getLogger(OidcOutboundOrchestrator.class.getName());

    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;
    private final OutboundConfig outboundConfig;
    private final ConcurrentMap<OutboundTarget, Optional<OidcOutboundPolicy>> targetPolicyCache =
            new ConcurrentHashMap<>();
    private final OidcClientCredentialsTokenManager clientCredentialsTokenManager =
            new OidcClientCredentialsTokenManager();
    private final OidcTokenExchangeTokenManager tokenExchangeTokenManager = new OidcTokenExchangeTokenManager();

    OidcOutboundOrchestrator(OidcProviderConfig providerConfig, OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this.tenantRuntimeRegistry = tenantRuntimeRegistry;
        OutboundConfig.Builder outboundConfig = OutboundConfig.builder();
        providerConfig.outboundTargets().forEach(outboundConfig::addTarget);
        this.outboundConfig = outboundConfig.build();
    }

    boolean isSupported(ProviderRequest providerRequest,
                        SecurityEnvironment outboundEnv,
                        EndpointConfig endpointConfig) {
        return tenantRuntimeRegistry.tenantConfig(providerRequest)
                .flatMap(tenantConfig -> outboundPolicy(tenantConfig, outboundEnv, endpointConfig))
                .isPresent();
    }

    private Optional<OidcOutboundPolicy> outboundPolicy(OidcTenantConfig tenantConfig,
                                                       SecurityEnvironment outboundEnv,
                                                       EndpointConfig endpointConfig) {
        if (!outboundTargetTlsAllowed(tenantConfig, outboundEnv)) {
            return Optional.empty();
        }

        Optional<OidcOutboundPolicy> endpointPolicy = endpointConfig == null
                ? Optional.empty()
                : endpointConfig.instance(OidcOutboundPolicy.class);
        if (endpointPolicy.isPresent()) {
            return endpointPolicy;
        }

        if (!outboundConfig.targets().isEmpty()) {
            return matchingTarget(outboundEnv)
                    .flatMap(target -> targetPolicyCache.computeIfAbsent(target, OidcOutboundPolicy::fromTarget));
        }
        return Optional.empty();
    }

    private Optional<OutboundTarget> matchingTarget(SecurityEnvironment outboundEnv) {
        if (outboundEnv == null || outboundEnv.targetUri() == null) {
            return Optional.empty();
        }
        String targetScheme = outboundEnv.targetUri().getScheme();
        SecurityEnvironment targetEnv = targetScheme == null
                ? outboundEnv
                : outboundEnv.derive()
                        .transport(targetScheme.toLowerCase(Locale.ROOT))
                        .build();
        return outboundConfig.findTarget(targetEnv);
    }

    private boolean outboundTargetTlsAllowed(OidcTenantConfig tenantConfig, SecurityEnvironment outboundEnv) {
        if (!tenantConfig.endpoints().tlsRequired()) {
            return true;
        }
        if (outboundEnv == null || outboundEnv.targetUri() == null) {
            return false;
        }
        String scheme = outboundEnv.targetUri().getScheme();
        return "https".equalsIgnoreCase(scheme);
    }

    OutboundSecurityResponse secure(ProviderRequest providerRequest,
                                    SecurityEnvironment outboundEnv,
                                    EndpointConfig endpointConfig) {
        Optional<OidcTenantContext> tenantContext = tenantRuntimeRegistry.tenantContext(providerRequest);
        if (tenantContext.isEmpty()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG, "OIDC outbound abstained: reason=no-tenant");
            }
        }
        if (tenantContext.filter(it -> !it.ready()).isPresent()) {
            OidcTenantContext unavailableTenant = tenantContext.orElseThrow();
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC outbound failed: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(unavailableTenant.tenantId())
                                   + ", reason=tenant-" + unavailableTenant.state().name().toLowerCase(Locale.ROOT));
            }
            return OidcResponseFactory.tenantUnavailableForOutbound();
        }

        Optional<OidcTenantContext> tlsBlockedTenant = tenantContext.filter(OidcTenantContext::ready)
                .filter(readyTenant -> !outboundTargetTlsAllowed(readyTenant.tenantConfig(), outboundEnv));
        if (tlsBlockedTenant.isPresent()) {
            OidcTenantContext readyTenant = tlsBlockedTenant.orElseThrow();
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC outbound abstained: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(readyTenant.tenantId())
                                   + ", reason=tls-required"
                                   + ", target=" + safeTargetUri(outboundEnv));
            }
            return OutboundSecurityResponse.abstain();
        }
        Optional<OidcOutboundPolicy> outboundPolicy = tenantContext
                .filter(OidcTenantContext::ready)
                .flatMap(readyTenant -> outboundPolicy(readyTenant.tenantConfig(), outboundEnv, endpointConfig));
        if (outboundPolicy.isEmpty()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                tenantContext.filter(OidcTenantContext::ready)
                        .ifPresent(readyTenant -> {
                            String tenantId = OidcDiagnostics.sanitizeLogValue(readyTenant.tenantId());
                            LOGGER.log(System.Logger.Level.DEBUG,
                                       "OIDC outbound abstained: tenant="
                                               + tenantId
                                               + ", reason=no-outbound-policy"
                                               + ", target=" + safeTargetUri(outboundEnv));
                        });
            }
            return OutboundSecurityResponse.abstain();
        }
        OidcOutboundPolicy policy = outboundPolicy.orElseThrow();
        if (policy.strategyCount() > 1) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                tenantContext.ifPresent(readyTenant -> {
                    String tenantId = OidcDiagnostics.sanitizeLogValue(readyTenant.tenantId());
                    LOGGER.log(System.Logger.Level.DEBUG,
                               "OIDC outbound failed: tenant="
                                       + tenantId
                                       + ", reason=ambiguous-outbound-policy");
                });
            }
            return OidcResponseFactory.ambiguousOutboundRequest();
        }
        if (policy.tokenPropagationEnabled()) {
            return propagateToken(providerRequest, outboundEnv, policy);
        }
        if (policy.clientCredentialsGrantEnabled()) {
            return secureWithClientCredentials(tenantContext.orElseThrow(), outboundEnv, policy);
        }
        if (policy.tokenExchangeEnabled()) {
            return secureWithTokenExchange(providerRequest, tenantContext.orElseThrow(), outboundEnv, policy);
        }
        return OutboundSecurityResponse.abstain();
    }

    private OutboundSecurityResponse propagateToken(ProviderRequest providerRequest,
                                                   SecurityEnvironment outboundEnv,
                                                   OidcOutboundPolicy outboundPolicy) {
        Optional<Subject> subject = providerRequest.subject();
        if (subject.isEmpty()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG, "OIDC token propagation abstained: reason=no-subject");
            }
            return OutboundSecurityResponse.abstain();
        }
        Optional<TokenCredential> credential = subject.orElseThrow()
                .publicCredential(TokenCredential.class);
        if (credential.isEmpty()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG, "OIDC token propagation abstained: reason=no-token-credential");
            }
            return OutboundSecurityResponse.abstain();
        }
        if (!audienceMatches(credential.orElseThrow(),
                             outboundPolicy.audience(),
                             outboundPolicy.audienceValidationEnabled())) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG, "OIDC token propagation abstained: reason=audience-mismatch");
            }
            return OutboundSecurityResponse.abstain();
        }
        return OutboundSecurityResponse.withHeaders(headersWithBearer(outboundEnv, credential.orElseThrow().token()));
    }

    private OutboundSecurityResponse secureWithClientCredentials(OidcTenantContext tenantContext,
                                                                 SecurityEnvironment outboundEnv,
                                                                 OidcOutboundPolicy outboundPolicy) {
        OidcTenantContext clientCredentialsContext;
        try {
            OidcClientAuthenticationConfigValidator.validateClientCredentialsGrant(tenantContext.tenantConfig(),
                                                                                  tenantContext.tenantConfig().endpoints(),
                                                                                  "Client Credentials Grant");
            clientCredentialsContext = tokenEndpointContext(tenantContext);
        } catch (RuntimeException e) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC Client Credentials Grant failed before token request: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(tenantContext.tenantId())
                                   + ", cause=" + OidcDiagnostics.safeExceptionType(e));
            }
            return OidcResponseFactory.clientCredentialsGrantFailed();
        }

        Instant now = outboundEnv == null ? Instant.now() : outboundEnv.time().toInstant();
        Optional<String> scope = outboundPolicy.clientCredentialsScope();
        List<String> resources = outboundPolicy.clientCredentialsResources();
        OidcTokenEndpointResult tokenResult = clientCredentialsTokenManager.token(clientCredentialsContext,
                                                                                 scope,
                                                                                 resources,
                                                                                 now);
        if (!tokenResult.succeeded()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC Client Credentials Grant failed: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(tenantContext.tenantId())
                                   + ", reason=token-endpoint-failure");
            }
            return OidcResponseFactory.clientCredentialsGrantFailed();
        }

        OidcTokenResponse tokenResponse = tokenResult.tokenResponse().orElseThrow();
        return OutboundSecurityResponse.withHeaders(headersWithBearer(outboundEnv, tokenResponse.accessToken()));
    }

    private OutboundSecurityResponse secureWithTokenExchange(ProviderRequest providerRequest,
                                                             OidcTenantContext tenantContext,
                                                             SecurityEnvironment outboundEnv,
                                                             OidcOutboundPolicy outboundPolicy) {
        Optional<TokenCredential> subjectToken = providerRequest.subject()
                .flatMap(subject -> subject.publicCredential(TokenCredential.class));
        if (subjectToken.isEmpty()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC Token Exchange abstained: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(tenantContext.tenantId())
                                   + ", reason=no-subject-token-credential");
            }
            return OutboundSecurityResponse.abstain();
        }

        OidcTenantContext tokenExchangeContext;
        try {
            OidcClientAuthenticationConfigValidator.validateTokenExchange(tenantContext.tenantConfig(),
                                                                         tenantContext.tenantConfig().endpoints());
            tokenExchangeContext = tokenEndpointContext(tenantContext);
        } catch (RuntimeException e) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC Token Exchange failed before token request: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(tenantContext.tenantId())
                                   + ", cause=" + OidcDiagnostics.safeExceptionType(e));
            }
            return OidcResponseFactory.tokenExchangeFailed();
        }

        Instant now = outboundEnv == null ? Instant.now() : outboundEnv.time().toInstant();
        OidcTokenExchangeResult tokenResult = tokenExchangeTokenManager.token(tokenExchangeContext,
                                                                              outboundPolicy,
                                                                              subjectToken.orElseThrow().token(),
                                                                              now);
        if (!tokenResult.succeeded()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC Token Exchange failed: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(tenantContext.tenantId())
                                   + ", reason=token-endpoint-failure");
            }
            return OidcResponseFactory.tokenExchangeFailed();
        }

        OidcTokenExchangeResponse tokenResponse = tokenResult.tokenResponse().orElseThrow();
        return OutboundSecurityResponse.withHeaders(headersWithBearer(outboundEnv, tokenResponse.accessToken()));
    }

    private OidcTenantContext tokenEndpointContext(OidcTenantContext tenantContext) {
        OidcProviderMetadata metadata = tenantContext.metadata();
        if (metadata.tokenEndpointUri().isEmpty() && metadata.wellKnownUri().isPresent()) {
            metadata = new OidcProviderMetadataLoader(tenantContext.webClient()).load(metadata);
        }
        metadata.tokenEndpointUri()
                .ifPresent(uri -> OidcEndpointUris.validateTokenEndpointUri(
                        uri,
                        OidcClientAuthenticationConfigValidator.tokenEndpointTlsRequired(tenantContext.tenantConfig())));
        return metadata == tenantContext.metadata()
                ? tenantContext
                : OidcTenantContext.ready(tenantContext.tenantId(),
                                          tenantContext.tenantConfig(),
                                          metadata,
                                          tenantContext.webClient());
    }

    private Map<String, List<String>> headersWithBearer(SecurityEnvironment outboundEnv, String token) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        if (outboundEnv != null) {
            headers.putAll(outboundEnv.headers());
        }
        headers.keySet().removeIf(HeaderNames.AUTHORIZATION.defaultCase()::equalsIgnoreCase);
        headers.put(HeaderNames.AUTHORIZATION.defaultCase(), List.of("Bearer " + token));
        return headers;
    }

    private boolean audienceMatches(TokenCredential credential,
                                    Optional<String> expectedAudience,
                                    boolean audienceValidationEnabled) {
        if (!audienceValidationEnabled) {
            return true;
        }
        if (expectedAudience.isEmpty()) {
            return false;
        }

        String audience = expectedAudience.orElseThrow();
        Optional<Boolean> jwtAudience = credential.getTokenInstance(Jwt.class)
                .flatMap(Jwt::audience)
                .map(audiences -> audiences.contains(audience));
        if (jwtAudience.isPresent()) {
            return jwtAudience.orElseThrow();
        }
        return credential.getTokenInstance(JsonObject.class)
                .map(claims -> jsonAudienceContains(claims, audience))
                .orElse(false);
    }

    private boolean jsonAudienceContains(JsonObject claims, String expectedAudience) {
        return claims.value("aud")
                .map(jsonValue -> {
                    if (jsonValue.type() == JsonValueType.STRING) {
                        return expectedAudience.equals(jsonValue.asString().value());
                    }
                    if (jsonValue.type() == JsonValueType.ARRAY) {
                        return jsonValue.asArray()
                                .values()
                                .stream()
                                .anyMatch(value -> value.type() == JsonValueType.STRING
                                        && expectedAudience.equals(value.asString().value()));
                    }
                    return false;
                })
                .orElse(false);
    }

    private static String safeTargetUri(SecurityEnvironment outboundEnv) {
        if (outboundEnv == null || outboundEnv.targetUri() == null) {
            return "<unknown>";
        }
        return OidcDiagnostics.safeUri(outboundEnv.targetUri());
    }
}
