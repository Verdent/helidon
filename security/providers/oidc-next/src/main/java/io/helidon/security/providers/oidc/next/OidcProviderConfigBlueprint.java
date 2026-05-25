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

import java.util.Map;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.security.spi.AuthenticationProvider;
import io.helidon.security.spi.OutboundSecurityProvider;
import io.helidon.security.spi.SecurityProvider;

/**
 * Configuration of the new OIDC security provider.
 */
@Prototype.Blueprint(decorator = OidcConfigSupport.ProviderDecorator.class)
@Prototype.Configured(value = OidcProviderService.PROVIDER_CONFIG_KEY, root = false)
@Prototype.Provides({SecurityProvider.class, AuthenticationProvider.class, OutboundSecurityProvider.class})
interface OidcProviderConfigBlueprint extends Prototype.Factory<OidcProvider> {

    /**
     * Provider name used by Helidon Security.
     *
     * @return provider name
     */
    @Option.Configured
    @Option.Default(OidcProviderService.PROVIDER_CONFIG_KEY)
    String providerName();

    /**
     * Whether authentication failures may be treated as optional by the provider.
     *
     * @return whether authentication is optional
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean optional();

    /**
     * Default tenant id.
     *
     * @return default tenant id
     */
    @Option.Configured
    Optional<String> defaultTenant();

    /**
     * Tenant resolution configuration.
     *
     * @return tenant resolution configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcTenantResolutionConfig tenantResolution();

    /**
     * Configured tenants keyed by tenant id.
     *
     * @return tenants
     */
    @Option.Configured
    @Option.Singular("tenant")
    Map<String, OidcTenantConfig> tenants();
}
