package io.helidon.security.providers.oidc.spi;

import io.helidon.config.Config;

/**
 * Java {@link java.util.ServiceLoader} service interface for multitenancy support.
 */
public interface TenantIdProvider {
    /**
     * Create a tenant ID finder API from Helidon config. This method is only called once.
     *
     * @param config configuration (may be empty)
     * @return a tenant id finder API
     */
    TenantIdFinder finder(Config config);
}
