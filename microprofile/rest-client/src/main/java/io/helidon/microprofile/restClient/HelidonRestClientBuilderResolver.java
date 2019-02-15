package io.helidon.microprofile.restClient;

import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.spi.RestClientBuilderResolver;

/**
 * Created by David Kral.
 */
public class HelidonRestClientBuilderResolver extends RestClientBuilderResolver {
    @Override
    public RestClientBuilder newBuilder() {
        return new HelidonRestClientBuilderImpl();
    }
}
