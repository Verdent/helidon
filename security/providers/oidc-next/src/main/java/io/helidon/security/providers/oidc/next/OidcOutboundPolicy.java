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

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import io.helidon.security.providers.common.OutboundTarget;

/**
 * Endpoint-level OIDC outbound policy.
 * <p>
 * Use this type as an {@link io.helidon.security.EndpointConfig} custom object when an outbound rule should apply to a
 * single outbound security request instead of a configured outbound target.
 */
public final class OidcOutboundPolicy {
    private final boolean tokenPropagation;
    private final boolean clientCredentialsGrant;
    private final boolean tokenExchange;
    private final Optional<String> audience;
    private final boolean audienceValidation;
    private final Optional<String> clientCredentialsScope;
    private final List<String> clientCredentialsResources;
    private final Optional<String> tokenExchangeScope;
    private final Optional<String> tokenExchangeResource;
    private final Optional<String> tokenExchangeAudience;

    private OidcOutboundPolicy(boolean tokenPropagation,
                               boolean clientCredentialsGrant,
                               boolean tokenExchange,
                               Optional<String> audience,
                               boolean audienceValidation,
                               Optional<String> clientCredentialsScope,
                               List<String> clientCredentialsResources,
                               Optional<String> tokenExchangeScope,
                               Optional<String> tokenExchangeResource,
                               Optional<String> tokenExchangeAudience) {
        this.tokenPropagation = tokenPropagation;
        this.clientCredentialsGrant = clientCredentialsGrant;
        this.tokenExchange = tokenExchange;
        this.audience = Objects.requireNonNull(audience);
        this.audienceValidation = audienceValidation;
        this.clientCredentialsScope = Objects.requireNonNull(clientCredentialsScope);
        this.clientCredentialsResources = List.copyOf(clientCredentialsResources);
        this.tokenExchangeScope = Objects.requireNonNull(tokenExchangeScope);
        this.tokenExchangeResource = Objects.requireNonNull(tokenExchangeResource);
        this.tokenExchangeAudience = Objects.requireNonNull(tokenExchangeAudience);
    }

    /**
     * Create a Token Propagation policy with audience validation.
     *
     * @param audience expected downstream audience
     * @return outbound policy
     */
    public static OidcOutboundPolicy tokenPropagation(String audience) {
        return tokenPropagation(Optional.of(nonBlank(audience, "audience")), true);
    }

    /**
     * Create a Token Propagation policy without audience validation.
     * <p>
     * This should be used only for testing, local development, or legacy opaque-token deployments.
     *
     * @return outbound policy
     */
    public static OidcOutboundPolicy tokenPropagationWithoutAudienceValidation() {
        return tokenPropagation(Optional.empty(), false);
    }

    private static OidcOutboundPolicy tokenPropagation(Optional<String> audience, boolean audienceValidation) {
        return new OidcOutboundPolicy(true,
                                      false,
                                      false,
                                      audience,
                                      audienceValidation,
                                      Optional.empty(),
                                      List.of(),
                                      Optional.empty(),
                                      Optional.empty(),
                                      Optional.empty());
    }

    /**
     * Create a Client Credentials Grant policy with no configured scopes or resource indicators.
     *
     * @return outbound policy
     */
    public static OidcOutboundPolicy clientCredentialsGrant() {
        return clientCredentialsGrant(List.of(), List.of());
    }

    /**
     * Create a Client Credentials Grant policy.
     *
     * @param scopes requested scopes
     * @param resources requested resource indicators
     * @return outbound policy
     */
    public static OidcOutboundPolicy clientCredentialsGrant(List<String> scopes, List<String> resources) {
        OidcScopeSupport.validateConfiguredScopes(scopes, "Client Credentials Grant scopes");
        OidcResourceIndicators.validate(resources, "Client Credentials Grant resources");
        String scope = OidcScopeSupport.serializeScopes(scopes);
        return new OidcOutboundPolicy(false,
                                      true,
                                      false,
                                      Optional.empty(),
                                      false,
                                      scope.isEmpty() ? Optional.empty() : Optional.of(scope),
                                      resources,
                                      Optional.empty(),
                                      Optional.empty(),
                                      Optional.empty());
    }

    /**
     * Create a Token Exchange policy with both a resource and an audience.
     *
     * @param scopes requested scopes
     * @param resource requested resource
     * @param audience requested audience
     * @return outbound policy
     */
    public static OidcOutboundPolicy tokenExchange(List<String> scopes, String resource, String audience) {
        return tokenExchange(scopes,
                             Optional.of(nonBlank(resource, "resource")),
                             Optional.of(nonBlank(audience, "audience")));
    }

    /**
     * Create a Token Exchange policy with only a requested resource.
     *
     * @param scopes requested scopes
     * @param resource requested resource
     * @return outbound policy
     */
    public static OidcOutboundPolicy tokenExchangeForResource(List<String> scopes, String resource) {
        return tokenExchange(scopes,
                             Optional.of(nonBlank(resource, "resource")),
                             Optional.empty());
    }

    /**
     * Create a Token Exchange policy with only a requested audience.
     *
     * @param scopes requested scopes
     * @param audience requested audience
     * @return outbound policy
     */
    public static OidcOutboundPolicy tokenExchangeForAudience(List<String> scopes, String audience) {
        return tokenExchange(scopes,
                             Optional.empty(),
                             Optional.of(nonBlank(audience, "audience")));
    }

    private static OidcOutboundPolicy tokenExchange(List<String> scopes,
                                                    Optional<String> requestedResource,
                                                    Optional<String> requestedAudience) {
        Objects.requireNonNull(requestedResource);
        Objects.requireNonNull(requestedAudience);
        if (requestedResource.isEmpty() && requestedAudience.isEmpty()) {
            throw new IllegalArgumentException("Token Exchange resource or audience must be configured");
        }
        OidcScopeSupport.validateConfiguredScopes(scopes, "Token Exchange scopes");
        requestedResource.ifPresent(value -> OidcResourceIndicators.validate(List.of(value), "Token Exchange resource"));
        String scope = OidcScopeSupport.serializeScopes(scopes);
        return new OidcOutboundPolicy(false,
                                      false,
                                      true,
                                      Optional.empty(),
                                      false,
                                      Optional.empty(),
                                      List.of(),
                                      scope.isEmpty() ? Optional.empty() : Optional.of(scope),
                                      requestedResource,
                                      requestedAudience);
    }

    static OidcOutboundPolicy tokenPropagationAndClientCredentialsGrant() {
        return new OidcOutboundPolicy(true,
                                      true,
                                      false,
                                      Optional.empty(),
                                      true,
                                      Optional.empty(),
                                      List.of(),
                                      Optional.empty(),
                                      Optional.empty(),
                                      Optional.empty());
    }

    static boolean targetClientCredentialsGrantEnabled(List<OutboundTarget> outboundTargets) {
        return outboundTargets.stream()
                .map(OidcOutboundPolicy::fromTarget)
                .flatMap(Optional::stream)
                .anyMatch(OidcOutboundPolicy::clientCredentialsGrantEnabled);
    }

    static boolean targetTokenExchangeEnabled(List<OutboundTarget> outboundTargets) {
        return outboundTargets.stream()
                .map(OidcOutboundPolicy::fromTarget)
                .flatMap(Optional::stream)
                .anyMatch(OidcOutboundPolicy::tokenExchangeEnabled);
    }

    static Optional<OidcOutboundPolicy> fromTarget(OutboundTarget target) {
        return target.customObject(OidcOutboundTargetConfig.class)
                .flatMap(OidcOutboundPolicy::fromTargetConfig)
                .or(() -> target.getConfig()
                        .map(OidcOutboundTargetConfig::create)
                        .flatMap(OidcOutboundPolicy::fromTargetConfig));
    }

    static Optional<OidcOutboundPolicy> fromTargetConfig(OidcOutboundTargetConfig config) {
        if (config.tokenPropagationEnabled()) {
            return Optional.of(tokenPropagation(config.audience(), config.audienceValidationEnabled()));
        }
        if (config.clientCredentialsGrantEnabled()) {
            return Optional.of(clientCredentialsGrant(config.clientCredentialsScopes(),
                                                      config.clientCredentialsResources()));
        }
        if (config.tokenExchangeEnabled()) {
            return Optional.of(tokenExchange(config.tokenExchangeScopes(),
                                             config.tokenExchangeResource(),
                                             config.tokenExchangeAudience()));
        }
        return Optional.empty();
    }

    boolean tokenPropagationEnabled() {
        return tokenPropagation;
    }

    boolean clientCredentialsGrantEnabled() {
        return clientCredentialsGrant;
    }

    boolean tokenExchangeEnabled() {
        return tokenExchange;
    }

    int strategyCount() {
        int count = tokenPropagation ? 1 : 0;
        count += clientCredentialsGrant ? 1 : 0;
        count += tokenExchange ? 1 : 0;
        return count;
    }

    Optional<String> audience() {
        return audience;
    }

    boolean audienceValidationEnabled() {
        return audienceValidation;
    }

    Optional<String> clientCredentialsScope() {
        return clientCredentialsScope;
    }

    List<String> clientCredentialsResources() {
        return clientCredentialsResources;
    }

    Optional<String> tokenExchangeScope() {
        return tokenExchangeScope;
    }

    Optional<String> tokenExchangeResource() {
        return tokenExchangeResource;
    }

    Optional<String> tokenExchangeAudience() {
        return tokenExchangeAudience;
    }

    private static String nonBlank(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || !value.equals(value.strip())) {
            throw new IllegalArgumentException(name + " must not be blank or padded");
        }
        return value;
    }
}
