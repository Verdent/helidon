package io.helidon.webclient;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.helidon.common.context.Context;
import io.helidon.common.http.HashParameters;
import io.helidon.common.http.Http;
import io.helidon.common.http.Parameters;
import io.helidon.config.Config;

/**
 * Implementation of the {@link ClientServiceRequest} interface
 */
class ClientServiceRequestImpl implements ClientServiceRequest {

    private final ClientRequestHeaders headers;
    private final Context context;
    private final Http.RequestMethod method;
    private final Http.Version version;
    private final URI uri;
    private final String query;
    private final Parameters queryParams;
    private final Path path;
    private final String fragment;
    private final HashParameters parameters;
    private final CompletableFuture<ClientServiceRequest> sent;
    private final CompletableFuture<ClientServiceRequest> complete;

    ClientServiceRequestImpl(ClientRequestBuilderImpl requestBuilder) {
        headers = requestBuilder.headers();
        context = requestBuilder.context();
        method = requestBuilder.method();
        version = requestBuilder.httpVersion();
        uri = requestBuilder.uri();
        query = requestBuilder.query();
        queryParams = queryParams();
        path = requestBuilder.path();
        fragment = requestBuilder.fragment();
        parameters = requestBuilder.properties();
        sent = new CompletableFuture<>();
        complete = new CompletableFuture<>();
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

    //EDIT: muzu odstranit kdyz v prvni verzi nechceme target configurace?
    @Override
    public Config serviceConfig() {
        return null;
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
