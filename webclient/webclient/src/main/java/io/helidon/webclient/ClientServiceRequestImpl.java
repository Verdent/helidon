package io.helidon.webclient;

import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.helidon.common.context.Context;
import io.helidon.common.http.HashParameters;
import io.helidon.common.http.Http;
import io.helidon.common.http.Parameters;
import io.helidon.config.Config;

import sun.management.Sensor;

/**
 * Implementation of the {@link ClientServiceRequest} interface
 */
class ClientServiceRequestImpl implements ClientServiceRequest {

    private final ClientRequestHeaders headers;
    private final Config config;
    private final Context context;
    private final Http.RequestMethod method;
    private final Http.Version version;
    private final URI uri;
    private final String query;
    private final Parameters queryParams;
    private final Path path;
    private final String fragment;
    private final HashParameters parameters;
    private final CompletionStage<ClientServiceRequest> sent;
    private final CompletionStage<ClientServiceRequest> complete;

    ClientServiceRequestImpl(ClientRequestBuilderImpl requestBuilder,
                             Config serviceConfig,
                             CompletionStage<ClientServiceRequest> sent,
                             CompletionStage<ClientServiceRequest> complete) {
        this.headers = requestBuilder.headers();
        this.context = requestBuilder.context();
        this.method = requestBuilder.method();
        this.version = requestBuilder.httpVersion();
        this.uri = requestBuilder.uri();
        this.query = requestBuilder.query();
        this.queryParams = queryParams();
        this.path = requestBuilder.path();
        this.fragment = requestBuilder.fragment();
        this.config = serviceConfig;
        this.parameters = new HashParameters(requestBuilder.properties());
        this.sent = sent;
        this.complete = complete;
    }

    @Override
    public ClientRequestHeaders headers() {
        return headers;
    }

    @Override
    public Context context() {
        return context;
    }

    @Override
    public CompletionStage<ClientServiceRequest> whenSent() {
        return sent;
    }

    @Override
    public CompletionStage<ClientServiceRequest> whenComplete() {
        return complete;
    }

    @Override
    public Parameters properties() {
        return parameters;
    }

    //EDIT: Kde presne to ma sedet?
    @Override
    public Config serviceConfig() {
        return config;
    }

    @Override
    public Http.RequestMethod method() {
        return method;
    }

    @Override
    public Http.Version version() {
        return version;
    }

    @Override
    public URI uri() {
        return uri;
    }

    @Override
    public String query() {
        return query;
    }

    @Override
    public Parameters queryParams() {
        return queryParams;
    }

    @Override
    public Path path() {
        return path;
    }

    @Override
    public String fragment() {
        return fragment;
    }
}
