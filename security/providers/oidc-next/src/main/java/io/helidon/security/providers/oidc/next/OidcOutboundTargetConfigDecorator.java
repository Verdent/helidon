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

import io.helidon.builder.api.Prototype;

final class OidcOutboundTargetConfigDecorator
        implements Prototype.BuilderDecorator<OidcOutboundTargetConfig.BuilderBase<?, ?>> {
    private static final System.Logger LOGGER = System.getLogger(OidcOutboundTargetConfigDecorator.class.getName());

    @Override
    public void decorate(OidcOutboundTargetConfig.BuilderBase<?, ?> target) {
        int strategyCount = 0;
        strategyCount += target.tokenPropagationEnabled() ? 1 : 0;
        strategyCount += target.clientCredentialsGrantEnabled() ? 1 : 0;
        strategyCount += target.tokenExchangeEnabled() ? 1 : 0;
        if (strategyCount > 1) {
            throw new IllegalArgumentException(
                    "Only one OIDC outbound strategy can be enabled on the same outbound target");
        }
        if (!target.clientCredentialsGrantEnabled() && !target.clientCredentialsScopes().isEmpty()) {
            throw new IllegalArgumentException(
                    "client-credentials-grant-enabled must be enabled when client-credentials-scopes is configured");
        }
        if (!target.clientCredentialsGrantEnabled() && !target.clientCredentialsResources().isEmpty()) {
            throw new IllegalArgumentException(
                    "client-credentials-grant-enabled must be enabled when client-credentials-resources is configured");
        }
        if (!target.tokenExchangeEnabled() && !target.tokenExchangeScopes().isEmpty()) {
            throw new IllegalArgumentException(
                    "token-exchange-enabled must be enabled when token-exchange-scopes is configured");
        }
        if (!target.tokenExchangeEnabled() && target.tokenExchangeResource().isPresent()) {
            throw new IllegalArgumentException(
                    "token-exchange-enabled must be enabled when token-exchange-resource is configured");
        }
        if (!target.tokenExchangeEnabled() && target.tokenExchangeAudience().isPresent()) {
            throw new IllegalArgumentException(
                    "token-exchange-enabled must be enabled when token-exchange-audience is configured");
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
        if (target.tokenExchangeEnabled()) {
            if (target.tokenExchangeResource().isEmpty() && target.tokenExchangeAudience().isEmpty()) {
                throw new IllegalArgumentException(
                        "token-exchange-resource or token-exchange-audience must be configured when Token Exchange "
                                + "is enabled");
            }
        }
        target.tokenExchangeAudience()
                .filter(audience -> audience.isBlank() || !audience.equals(audience.strip()))
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException("token-exchange-audience must not be blank or padded");
                });
        OidcScopeSupport.validateConfiguredScopes(target.clientCredentialsScopes(), "client-credentials-scopes");
        OidcResourceIndicators.validate(target.clientCredentialsResources(), "client-credentials-resources");
        OidcScopeSupport.validateConfiguredScopes(target.tokenExchangeScopes(), "token-exchange-scopes");
        target.tokenExchangeResource()
                .ifPresent(resource -> OidcResourceIndicators.validate(List.of(resource), "token-exchange-resource"));
    }
}
