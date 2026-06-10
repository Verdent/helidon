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
import io.helidon.security.jwt.Jwt;
import io.helidon.security.providers.common.OutboundConfig;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.common.TokenCredential;

final class OidcOutboundOrchestrator {
    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;
    private final OutboundConfig outboundConfig;
    private final ConcurrentMap<OutboundTarget, Optional<OidcOutboundPolicy>> targetPolicyCache = new ConcurrentHashMap<>();
    private final OidcClientCredentialsTokenManager clientCredentialsTokenManager = new OidcClientCredentialsTokenManager();

    private OidcOutboundOrchestrator(OidcProviderConfig providerConfig,
                                     OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this.tenantRuntimeRegistry = tenantRuntimeRegistry;
        OutboundConfig.Builder outboundConfig = OutboundConfig.builder();
        providerConfig.outboundTargets().forEach(outboundConfig::addTarget);
        this.outboundConfig = outboundConfig.build();
    }

    static OidcOutboundOrchestrator create(OidcProviderConfig providerConfig,
                                           OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcOutboundOrchestrator(providerConfig, tenantRuntimeRegistry);
    }

    boolean isSupported(ProviderRequest providerRequest,
                        SecurityEnvironment outboundEnv,
                        EndpointConfig outboundConfig) {
        return tenantRuntimeRegistry.tenantConfig(providerRequest)
                .flatMap(tenantConfig -> outboundPolicy(tenantConfig, outboundEnv, outboundConfig))
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
                                    EndpointConfig outboundConfig) {
        Optional<OidcTenantContext> tenantContext = tenantRuntimeRegistry.tenantContext(providerRequest);
        if (tenantContext.filter(it -> !it.ready()).isPresent()) {
            return OidcResponseFactory.tenantUnavailableForOutbound(tenantContext.orElseThrow());
        }

        Optional<OidcOutboundPolicy> outboundPolicy = tenantContext
                .filter(OidcTenantContext::ready)
                .flatMap(readyTenant -> outboundPolicy(readyTenant.tenantConfig(), outboundEnv, outboundConfig));
        if (outboundPolicy.isEmpty()) {
            return OutboundSecurityResponse.abstain();
        }
        OidcOutboundPolicy policy = outboundPolicy.orElseThrow();
        if (policy.tokenPropagationEnabled() && policy.clientCredentialsGrantEnabled()) {
            return OidcResponseFactory.ambiguousOutboundRequest();
        }
        if (policy.tokenPropagationEnabled()) {
            return propagateToken(providerRequest, outboundEnv, policy);
        }
        if (policy.clientCredentialsGrantEnabled()) {
            return secureWithClientCredentials(tenantContext.orElseThrow(), outboundEnv, policy);
        }
        return OutboundSecurityResponse.abstain();
    }

    private OutboundSecurityResponse propagateToken(ProviderRequest providerRequest,
                                                   SecurityEnvironment outboundEnv,
                                                   OidcOutboundPolicy outboundPolicy) {
        return providerRequest.subject()
                .flatMap(subject -> subject.publicCredential(TokenCredential.class))
                .filter(credential -> audienceMatches(credential,
                                                      outboundPolicy.audience(),
                                                      outboundPolicy.audienceValidationEnabled()))
                .map(credential -> OutboundSecurityResponse.withHeaders(headersWithBearer(outboundEnv,
                                                                                          credential.token())))
                .orElseGet(OutboundSecurityResponse::abstain);
    }

    private OutboundSecurityResponse secureWithClientCredentials(OidcTenantContext tenantContext,
                                                                 SecurityEnvironment outboundEnv,
                                                                 OidcOutboundPolicy outboundPolicy) {
        OidcTenantContext clientCredentialsContext;
        try {
            OidcConfigSupport.validateClientCredentialsGrant(tenantContext.tenantConfig(),
                                                             tenantContext.tenantConfig().endpoints(),
                                                             "Client Credentials Grant");
            clientCredentialsContext = clientCredentialsContext(tenantContext);
        } catch (RuntimeException e) {
            return OidcResponseFactory.clientCredentialsGrantFailed(OidcTokenEndpointResult.failure(e.getMessage(), e));
        }

        Instant now = outboundEnv == null ? Instant.now() : outboundEnv.time().toInstant();
        OidcTokenEndpointResult tokenResult = clientCredentialsTokenManager.token(clientCredentialsContext,
                                                                                 outboundPolicy.clientCredentialsScope(),
                                                                                 outboundPolicy.clientCredentialsResources(),
                                                                                 now);
        if (!tokenResult.succeeded()) {
            return OidcResponseFactory.clientCredentialsGrantFailed(tokenResult);
        }

        OidcTokenResponse tokenResponse = tokenResult.tokenResponse().orElseThrow();
        return OutboundSecurityResponse.withHeaders(headersWithBearer(outboundEnv, tokenResponse.accessToken()));
    }

    private OidcTenantContext clientCredentialsContext(OidcTenantContext tenantContext) {
        OidcProviderMetadata metadata = tenantContext.metadata();
        if (metadata.tokenEndpointUri().isEmpty() && metadata.wellKnownUri().isPresent()) {
            metadata = new OidcProviderMetadataLoader(tenantContext.webClient()).load(metadata);
        }
        metadata.tokenEndpointUri()
                .ifPresent(uri -> OidcConfigSupport.validateTokenEndpointUri(
                        uri,
                        OidcConfigSupport.tokenEndpointTlsRequired(tenantContext.tenantConfig())));
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
}
