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
    private final OutboundConfig outboundTargetConfig;
    private final ConcurrentMap<OutboundTarget, Optional<OidcOutboundPolicy>> targetPolicyCache = new ConcurrentHashMap<>();
    private final OidcClientCredentialsTokenManager clientCredentialsTokenManager = new OidcClientCredentialsTokenManager();

    private OidcOutboundOrchestrator(OidcTenantRuntimeRegistry tenantRuntimeRegistry,
                                     List<OutboundTarget> outboundTargets) {
        this.tenantRuntimeRegistry = tenantRuntimeRegistry;
        OutboundConfig.Builder builder = OutboundConfig.builder();
        outboundTargets.forEach(builder::addTarget);
        this.outboundTargetConfig = builder.build();
    }

    static OidcOutboundOrchestrator create(OidcProviderConfig config,
                                           OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcOutboundOrchestrator(tenantRuntimeRegistry, config.outboundTargets());
    }

    static OidcOutboundOrchestrator create(OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcOutboundOrchestrator(tenantRuntimeRegistry, List.of());
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
                                                       EndpointConfig outboundConfig) {
        if (!outboundTargetTlsAllowed(tenantConfig, outboundEnv)) {
            return Optional.empty();
        }

        Optional<OidcOutboundPolicy> endpointPolicy = outboundConfig == null
                ? Optional.empty()
                : outboundConfig.instance(OidcOutboundPolicy.class);
        if (endpointPolicy.isPresent()) {
            return endpointPolicy;
        }

        Optional<OidcOutboundPolicy> tenantPolicy = OidcConfigSupport.outboundPolicy(tenantConfig);
        if (!outboundTargetConfig.targets().isEmpty()) {
            return matchingTarget(outboundEnv)
                    .flatMap(target -> targetPolicy(target)
                            .or(() -> targetAudiencePolicy(target, tenantPolicy))
                            .or(() -> tenantPolicy));
        }
        if (tenantPolicy.filter(OidcOutboundPolicy::tokenPropagationEnabled).isPresent()) {
            return Optional.empty();
        }
        return tenantPolicy;
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
        return outboundTargetConfig.findTarget(targetEnv);
    }

    private boolean outboundTargetTlsAllowed(OidcTenantConfig tenantConfig, SecurityEnvironment outboundEnv) {
        if (!tenantConfig.endpoints().tlsRequired() || outboundEnv == null || outboundEnv.targetUri() == null) {
            return true;
        }
        String scheme = outboundEnv.targetUri().getScheme();
        return scheme == null || "https".equalsIgnoreCase(scheme);
    }

    private Optional<OidcOutboundPolicy> targetPolicy(OutboundTarget target) {
        return targetPolicyCache.computeIfAbsent(target, OidcOutboundPolicy::fromTarget);
    }

    private Optional<OidcOutboundPolicy> targetAudiencePolicy(OutboundTarget target,
                                                             Optional<OidcOutboundPolicy> tenantPolicy) {
        if (tenantPolicy.filter(OidcOutboundPolicy::tokenPropagationEnabled).isEmpty()) {
            return Optional.empty();
        }
        return OidcOutboundPolicy.targetAudience(target)
                .map(OidcOutboundPolicy::tokenPropagation);
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
        OidcProtocolOperation operation = OidcRequestClassifier.classify(outboundPolicy);

        return switch (operation) {
            case TOKEN_PROPAGATION -> propagateToken(providerRequest, outboundEnv, outboundPolicy.orElseThrow());
            case CLIENT_CREDENTIALS_GRANT -> secureWithClientCredentials(tenantContext.orElseThrow(), outboundEnv);
            case AMBIGUOUS -> OidcResponseFactory.ambiguousOutboundRequest();
            case BEARER_TOKEN_INVALID_REQUEST,
                    BEARER_TOKEN_AUTHENTICATION,
                    AUTHORIZATION_CODE_FLOW_INITIATION,
                    AUTHORIZATION_RESPONSE,
                    RP_INITIATED_LOGOUT,
                    ABSTAIN -> OutboundSecurityResponse.abstain();
        };
    }

    private OutboundSecurityResponse propagateToken(ProviderRequest providerRequest,
                                                   SecurityEnvironment outboundEnv,
                                                   OidcOutboundPolicy outboundPolicy) {
        return providerRequest.subject()
                .flatMap(subject -> subject.publicCredential(TokenCredential.class))
                .filter(credential -> audienceMatches(credential, outboundPolicy.audience()))
                .map(credential -> OutboundSecurityResponse.withHeaders(headersWithBearer(outboundEnv,
                                                                                          credential.token())))
                .orElseGet(OutboundSecurityResponse::abstain);
    }

    private OutboundSecurityResponse secureWithClientCredentials(OidcTenantContext tenantContext,
                                                                 SecurityEnvironment outboundEnv) {
        try {
            OidcConfigSupport.validateClientCredentialsGrant(tenantContext.tenantConfig(),
                                                             tenantContext.tenantConfig().endpoints(),
                                                             "Client Credentials Grant");
            tenantContext.metadata()
                    .tokenEndpointUri()
                    .ifPresent(uri -> OidcConfigSupport.validateTokenEndpointUri(
                            uri,
                            tenantContext.tenantConfig().endpoints().tlsRequired()));
        } catch (RuntimeException e) {
            return OidcResponseFactory.clientCredentialsGrantFailed(OidcTokenEndpointResult.failure(e.getMessage(), e));
        }

        OidcTokenEndpointResult tokenResult = clientCredentialsTokenManager.token(tenantContext, now(outboundEnv));
        if (!tokenResult.succeeded()) {
            return OidcResponseFactory.clientCredentialsGrantFailed(tokenResult);
        }

        OidcTokenResponse tokenResponse = tokenResult.tokenResponse().orElseThrow();
        return OutboundSecurityResponse.withHeaders(headersWithBearer(outboundEnv, tokenResponse.accessToken()));
    }

    private Map<String, List<String>> headersWithBearer(SecurityEnvironment outboundEnv, String token) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        if (outboundEnv != null) {
            headers.putAll(outboundEnv.headers());
        }
        headers.put(HeaderNames.AUTHORIZATION.defaultCase(), List.of("Bearer " + token));
        return headers;
    }

    private boolean audienceMatches(TokenCredential credential, Optional<String> expectedAudience) {
        if (expectedAudience.isEmpty()) {
            return true;
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

    private Instant now(SecurityEnvironment outboundEnv) {
        if (outboundEnv == null) {
            return Instant.now();
        }
        return outboundEnv.time().toInstant();
    }
}
