package io.helidon.security.providers.oidc.spi;

import io.helidon.config.Config;

/**
 * Java {@link java.util.ServiceLoader} service interface for multitenancy support.
 */
public interface TenantConfigProvider {
    /**
     * Create a tenant configuration API from Helidon config. This method is only called once.
     *
     * @param config configuration (may be empty)
     * @return a tenant configuration API
     */
    TenantConfigFinder createTenantConfigFinder(Config config);
}
