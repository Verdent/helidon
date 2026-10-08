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

final class OidcOutboundPolicyConfigDecorator
        implements Prototype.BuilderDecorator<OidcOutboundPolicyConfig.BuilderBase<?, ?>> {
    private static final System.Logger LOGGER = System.getLogger(OidcOutboundPolicyConfigDecorator.class.getName());

    @Override
    public void decorate(OidcOutboundPolicyConfig.BuilderBase<?, ?> target) {
        OidcOutboundStrategy strategy = target.strategy();
        if (strategy != OidcOutboundStrategy.CLIENT_CREDENTIALS && !target.clientCredentialsScopes().isEmpty()) {
            throw new IllegalArgumentException(
                    "strategy must be CLIENT_CREDENTIALS when client-credentials-scopes is configured");
        }
        if (strategy != OidcOutboundStrategy.CLIENT_CREDENTIALS && !target.clientCredentialsResources().isEmpty()) {
            throw new IllegalArgumentException(
                    "strategy must be CLIENT_CREDENTIALS when client-credentials-resources is configured");
        }
        if (strategy != OidcOutboundStrategy.TOKEN_EXCHANGE && !target.tokenExchangeScopes().isEmpty()) {
            throw new IllegalArgumentException(
                    "strategy must be TOKEN_EXCHANGE when token-exchange-scopes is configured");
        }
        if (strategy != OidcOutboundStrategy.TOKEN_EXCHANGE && target.tokenExchangeResource().isPresent()) {
            throw new IllegalArgumentException(
                    "strategy must be TOKEN_EXCHANGE when token-exchange-resource is configured");
        }
        if (strategy != OidcOutboundStrategy.TOKEN_EXCHANGE && target.tokenExchangeAudience().isPresent()) {
            throw new IllegalArgumentException(
                    "strategy must be TOKEN_EXCHANGE when token-exchange-audience is configured");
        }
        target.audience()
                .filter(audience -> audience.isBlank() || !audience.equals(audience.strip()))
                .ifPresent(_ -> {
                    throw new IllegalArgumentException("audience must not be blank or padded");
                });
        if (strategy == OidcOutboundStrategy.TOKEN_PROPAGATION) {
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
                if (LOGGER.isLoggable(System.Logger.Level.WARNING)) {
                    LOGGER.log(System.Logger.Level.WARNING,
                               "Token Propagation audience validation is disabled. Propagated bearer tokens will not "
                                       + "be checked locally for the downstream audience and this should be used only "
                                       + "for testing, local development, or legacy opaque-token deployments.");
                }
            }
        }
        if (strategy == OidcOutboundStrategy.TOKEN_EXCHANGE) {
            if (target.tokenExchangeResource().isEmpty() && target.tokenExchangeAudience().isEmpty()) {
                throw new IllegalArgumentException(
                        "token-exchange-resource or token-exchange-audience must be configured when Token Exchange "
                                + "is enabled");
            }
        }
        target.tokenExchangeAudience()
                .filter(audience -> audience.isBlank() || !audience.equals(audience.strip()))
                .ifPresent(_ -> {
                    throw new IllegalArgumentException("token-exchange-audience must not be blank or padded");
                });
        OidcScopeSupport.validateConfiguredScopes(target.clientCredentialsScopes(), "client-credentials-scopes");
        OidcResourceIndicators.validate(target.clientCredentialsResources(), "client-credentials-resources");
        OidcScopeSupport.validateConfiguredScopes(target.tokenExchangeScopes(), "token-exchange-scopes");
        target.tokenExchangeResource()
                .ifPresent(resource -> OidcResourceIndicators.validate(List.of(resource), "token-exchange-resource"));
    }
}
