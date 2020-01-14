package io.helidon.tracing.rest.client;

import io.helidon.config.Config;
import io.helidon.webclient.spi.ClientService;
import io.helidon.webclient.spi.ClientServiceProvider;

/**
 * TODO Javadoc
 */
public class ClientTracingProvider implements ClientServiceProvider {
    @Override
    public String configKey() {
        return "tracing";
    }

    @Override
    public ClientService create(Config config) {
        return ClientTracing.create();
    }
}
