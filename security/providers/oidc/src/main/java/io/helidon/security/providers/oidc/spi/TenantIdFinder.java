package io.helidon.security.providers.oidc.spi;

import java.util.Optional;

import io.helidon.security.ProviderRequest;

public interface TenantIdFinder {
    /**
     * Identify a tenant from the request.
     *
     * @param providerRequest request of the security provider with access to headers
     *                       (see {@link ProviderRequest#env()}), and other information about the request
     * @return the identified tenant id, or empty option if tenant id cannot be identified from the request
     */
    Optional<String> tenantId(ProviderRequest providerRequest);
}
