/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
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
    ClientRequestBuilder uri(String uri);

    ClientRequestBuilder uri(URL url);

    ClientRequestBuilder uri(URI uri);

    /**
     * Add a property to be used by a {@link io.helidon.webclient.spi.ClientService}
     *
     * @param propertyName
     * @param propertyValue
     * @return
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
     * Add (or replace) a request header.
     *
     * @param header
     * @param values
     * @return
     * @see #headers()
     */
    ClientRequestBuilder header(String header, String... values);

    /**
     * Get a (mutable) instance of outgoing headers
     *
     * @return
     */
    ClientRequestHeaders headers();

    /**
     * Add a query parameter.
     *
     * @param name
     * @param values
     * @return
     */
    ClientRequestBuilder queryParam(String name, String... values);

    /**
     * Override client proxy configuration
     *
     * @param proxy
     * @return
     */
    ClientRequestBuilder proxy(Proxy proxy);

    /**
     * Configure headers. Copy all headers from supplied {@link Headers} instance.
     *
     * @param headers to copy
     * @return updated builder instance
     */
    ClientRequestBuilder headers(Headers headers);

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

    ClientRequestBuilder fragment(String fragment);

    ClientRequestBuilder path(HttpRequest.Path path);

    ClientRequestBuilder contentType(MediaType mediaType);

    ClientRequestBuilder contentLength(long length);

    ClientRequestBuilder ifModifiedSince(ZonedDateTime time);

    ClientRequestBuilder ifNoneMatch(String... etags);

    ClientRequestBuilder accept(MediaType... mediaTypes);

    CompletionStage<ClientResponse> redirect();

    <T> CompletionStage<T> request(Class<T> responseType);

    <T> CompletionStage<T> request(GenericType<T> responseType);

    default CompletionStage<ClientResponse> request() {
        return request(ClientResponse.class);
    }

    CompletionStage<ClientResponse> submit();

    // TODO this must work with multipart
    // send multiple files from client to server -> memory, threads
    <T> CompletionStage<T> submit(Flow.Publisher<DataChunk> requestEntity, Class<T> responseType);

    <T> CompletionStage<T> submit(Object requestEntity, Class<T> responseType);

    CompletionStage<ClientResponse> submit(Flow.Publisher<DataChunk> requestEntity);

    CompletionStage<ClientResponse> submit(Object requestEntity);

    interface ClientRequest extends HttpRequest {

        ClientRequestHeaders headers();

        RequestConfiguration configuration();

        Map<String, Object> properties();

        Proxy proxy();

        int redirectionCount();

    }
}
