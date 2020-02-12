package io.helidon.webclient;

import io.helidon.common.context.Context;

/**
 * TODO Javadoc
 */
class ClientServiceResponseImpl implements ClientServiceResponse {

    private final Context context;
    private final ClientResponseHeaders headers;

    ClientServiceResponseImpl(Context context, ClientResponseHeaders headers) {
        this.context = context;
        this.headers = headers;
    }

    @Override
    public ClientResponseHeaders headers() {
        return headers;
    }

    @Override
    public Context context() {
        return context;
    }

}
