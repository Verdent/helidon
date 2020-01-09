/*
 * Copyright (c) 2018, 2020 Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.helidon.webclient;

import java.net.URI;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;

import io.helidon.common.GenericType;
import io.helidon.common.context.Context;
import io.helidon.common.http.DataChunk;
import io.helidon.common.http.Headers;
import io.helidon.common.http.Http;
import io.helidon.common.http.HttpRequest;
import io.helidon.common.http.MediaType;
import io.helidon.common.http.Parameters;
import io.helidon.common.reactive.Flow;

/**
 * Fluent API builder that is used by {@link WebClient} to create an outgoing request.
 */
public interface ClientRequestBuilder {

    /**
     * String format of the request uri.
     *
     * @param uri request uri
     * @return updated builder instance
     */
    ClientRequestBuilder uri(String uri);

    /**
     * Request {@link URL}.
     *
     * @param url request url
     * @return updated builder instance
     */
    ClientRequestBuilder uri(URL url);

    /**
     * Request {@link URI}.
     *
     * @param uri request uri
     * @return updated builder instance
     */
    ClientRequestBuilder uri(URI uri);

    /**
     * Add a property to be used by a {@link io.helidon.webclient.spi.ClientService}.
     *
     * @param propertyName property name
     * @param propertyValue property value
     * @return updated builder instance
     */
    ClientRequestBuilder property(String propertyName, Object propertyValue);

    /**
     * Explicitly configure a context to use.
     * This method is not needed when running within a scope of a Helidon server, such as
     *  Web Server, gRPC Server, MicroProfile Server, or when processing a Helidon message consumer.
     *
     * @param context context to be used by the outbound request, to look for security context, parent tracing span and similar
     * @return updated builder instance
     */
    ClientRequestBuilder context(Context context);

    /**
     * Get a (mutable) instance of outgoing headers.
     *
     * @return client request headers
     */
    ClientRequestHeaders headers();

    /**
     * Add a query parameter.
     *
     * @param name query name
     * @param values query value
     * @return updated builder instance
     */
    ClientRequestBuilder queryParam(String name, String... values);

    /**
     * Override client proxy configuration.
     *
     * @param proxy request proxy
     * @return updated builder instance
     */
    ClientRequestBuilder proxy(Proxy proxy);

    /**
     * Configure headers. Copy all headers from supplied {@link Headers} instance.
     *
     * @param headers to copy
     * @return updated builder instance
     */
    ClientRequestBuilder headers(Headers headers);

    //TODO EDIT:
    ClientRequestBuilder headers(Function<ClientRequestHeaders, Headers> headers);

    /**
     * Configure query parameters.
     * Copy all query parameters from supplied {@link Parameters} instance.
     *
     * @param queryParams to copy
     * @return updated builder instance
     */
    ClientRequestBuilder queryParams(Parameters queryParams);

    /**
     * Register an entity handler.
     *
     * @param handler
     * @return updated builder instance
     */
    ClientRequestBuilder register(ClientContentHandler<?> handler);

    /**
     * Sets http version.
     *
     * @param httpVersion http version
     * @return updated builder instance
     */
    ClientRequestBuilder httpVersion(Http.Version httpVersion);

    /**
     * Fragment of the request.
     *
     * @param fragment request fragment
     * @return updated builder instance
     */
    ClientRequestBuilder fragment(String fragment);

    /**
     * Path of the request.
     *
     * @param path path
     * @return updated builder instance
     */
    ClientRequestBuilder path(HttpRequest.Path path);

    /**
     * Content type of the request.
     *
     * @param contentType content type
     * @return updated builder instance
     */
    ClientRequestBuilder contentType(MediaType contentType);

    /**
     * Media types which are accepted in the response.
     *
     * @param mediaTypes media types
     * @return updated builder instance
     */
    ClientRequestBuilder accept(MediaType... mediaTypes);

    /**
     * Performs prepared request and transforms response to requested type.
     *
     * When transformation is done the returned {@link CompletionStage} is notified.
     *
     * @param responseType requested response type
     * @param <T> response type
     * @return request completion stage
     */
    <T> CompletionStage<T> request(Class<T> responseType);
    /**
     * Performs prepared request and transforms response to requested type.
     *
     * When transformation is done the returned {@link CompletionStage} is notified.
     *
     * @param responseType requested response type
     * @param <T> response type
     * @return request completion stage
     */
    <T> CompletionStage<T> request(GenericType<T> responseType);

    /**
     * Performs prepared request without expecting to receive any specific type.
     *
     * Response is not converted and returned {@link CompletionStage} is notified.
     *
     * @return request completion stage
     */
    default CompletionStage<ClientResponse> request() {
        return request(ClientResponse.class);
    }

    CompletionStage<ClientResponse> submit();

    // TODO this must work with multipart
    // send multiple files from client to server -> memory, threads
    // Prozkoumat jestli je tohle jiz hotove na serveru
    // Mozna se zeptat romaina az bude client mergenutej???

    /**
     * Performs prepared request and submitting request entity using {@link Flow.Publisher}.
     *
     * When response is received, it is converted to response type and returned {@link CompletionStage}
     * is notified.
     *
     * @param requestEntity request entity
     * @param responseType requested response type
     * @param <T> response type
     * @return request completion stage
     */
    <T> CompletionStage<T> submit(Flow.Publisher<DataChunk> requestEntity, Class<T> responseType);

    /**
     * Performs prepared request and submitting request entity.
     *
     * When response is received, it is converted to response type and returned {@link CompletionStage}
     * is notified.
     *
     * @param requestEntity request entity
     * @param responseType requested response type
     * @param <T> response type
     * @return request completion stage
     */
    <T> CompletionStage<T> submit(Object requestEntity, Class<T> responseType);

    /**
     * Performs prepared request and submitting request entity using {@link Flow.Publisher}.
     *
     * When response is received, it is not converted to any other specific type and returned {@link CompletionStage}
     * is notified.
     *
     * @param requestEntity request entity
     * @return request completion stage
     */
    CompletionStage<ClientResponse> submit(Flow.Publisher<DataChunk> requestEntity);

    /**
     * Performs prepared request and submitting request entity.
     *
     * When response is received, it is not converted to any other specific type and returned {@link CompletionStage}
     * is notified.
     *
     * @param requestEntity request entity
     * @return request completion stage
     */
    CompletionStage<ClientResponse> submit(Object requestEntity);

    /**
     * Request to a server. Contains all information about used request headers, configuration etc.
     */
    interface ClientRequest extends HttpRequest {

        /**
         * Headers which are used in current request.
         *
         * @return request headers
         */
        ClientRequestHeaders headers();

        /**
         * Current request configuration.
         *
         * @return request configuration
         */
        RequestConfiguration configuration();

        //TODO javadoc
        Map<String, Object> properties();

        /**
         * Proxy used by current request.
         *
         * @return proxy
         */
        Proxy proxy();

        /**
         * Returns how many times our request has been redirected.
         *
         * @return redirection count
         */
        int redirectionCount();

    }
}
