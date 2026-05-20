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

import java.util.Objects;
import java.util.function.Consumer;

import io.helidon.builder.api.RuntimeType;
import io.helidon.config.Config;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.spi.AuthenticationProvider;
import io.helidon.security.spi.OutboundSecurityProvider;

/**
 * New OpenID Connect security provider.
 */
public final class OidcProvider
        implements AuthenticationProvider, OutboundSecurityProvider, RuntimeType.Api<OidcProviderConfig> {
    private final OidcProviderConfig config;

    private OidcProvider(OidcProviderConfig config) {
        this.config = Objects.requireNonNull(config);
    }

    /**
     * Fluent API builder to set up an instance.
     *
     * @return a new builder
     */
    public static OidcProviderConfig.Builder builder() {
        return OidcProviderConfig.builder();
    }

    /**
     * Create a provider from configuration.
     *
     * @param config provider configuration
     * @return new provider instance
     */
    public static OidcProvider create(Config config) {
        return builder()
                .config(config)
                .build();
    }

    /**
     * Create a provider from its configuration.
     *
     * @param config provider configuration
     * @return new provider instance
     */
    public static OidcProvider create(OidcProviderConfig config) {
        return new OidcProvider(config);
    }

    /**
     * Create a provider customizing its configuration.
     *
     * @param consumer provider configuration builder consumer
     * @return new provider instance
     */
    public static OidcProvider create(Consumer<OidcProviderConfig.Builder> consumer) {
        return builder()
                .update(consumer)
                .build();
    }

    /**
     * Create a provider with defaults.
     *
     * @return new provider instance
     */
    public static OidcProvider create() {
        return builder().build();
    }

    @Override
    public OidcProviderConfig prototype() {
        return config;
    }

    @Override
    public AuthenticationResponse authenticate(ProviderRequest providerRequest) {
        return AuthenticationResponse.abstain();
    }

    @Override
    public boolean isOutboundSupported(ProviderRequest providerRequest,
                                       SecurityEnvironment outboundEnv,
                                       EndpointConfig outboundConfig) {
        return false;
    }

    @Override
    public OutboundSecurityResponse outboundSecurity(ProviderRequest providerRequest,
                                                     SecurityEnvironment outboundEnv,
                                                     EndpointConfig outboundConfig) {
        return OutboundSecurityResponse.abstain();
    }
}
