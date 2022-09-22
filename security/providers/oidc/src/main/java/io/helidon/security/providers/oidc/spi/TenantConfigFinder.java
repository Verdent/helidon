package io.helidon.security.providers.oidc.spi;

import java.util.Optional;
import java.util.function.Consumer;

import io.helidon.security.providers.oidc.common.OidcConfig;

/**
 * Configuration of a tenant.
 */
public interface TenantConfigFinder {

    /**
     * Open ID Configuration for this tenant.
     *
     * @param tenantId identified tenant, or {@link io.helidon.security.providers.oidc.common.OidcServiceConfig#DEFAULT_TENANT_ID}
     *                 if tenant was not identified, or default was chosen
     * @return open ID connect configuration, or empty optional in case we are missing configuration (this will fail the request
     * if the provider is not optional)
     */
    Optional<OidcConfig> config(String tenantId);

    /**
     * Register a change listener. When configuration is updated, call the consumer to remove the cached data for this tenant.
     *
     * @param tenantIdChangeConsumer consumer of tenant configuration changes
     */
    void onChange(Consumer<String> tenantIdChangeConsumer);
}
