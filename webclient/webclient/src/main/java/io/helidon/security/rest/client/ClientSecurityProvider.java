package io.helidon.security.rest.client;

import io.helidon.config.Config;
import io.helidon.tracing.rest.client.ClientTracing;
import io.helidon.webclient.spi.ClientService;
import io.helidon.webclient.spi.ClientServiceProvider;

/**
 * Client security SPI provider.
 */
public class ClientSecurityProvider implements ClientServiceProvider {
    @Override
    public String configKey() {
        return "security";
    }

    @Override
    public ClientService create(Config config) {
        return ClientSecurity.create();
    }
}
