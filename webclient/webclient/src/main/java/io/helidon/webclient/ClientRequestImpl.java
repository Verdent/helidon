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
import java.util.HashMap;
import java.util.Map;

import io.helidon.common.http.Http;
import io.helidon.common.http.Parameters;
import io.helidon.common.http.ReadOnlyParameters;

/**
 * TODO Javadoc
 */
class ClientRequestImpl implements ClientRequestBuilder.ClientRequest {

    private final URI uri;
    private final RequestConfiguration requestConfiguration;
    private final ClientRequestHeaders clientRequestHeaders;
    private final Http.RequestMethod requestMethod;
    private final Http.Version httpVersion;
    private final Map<String, Object> properties;
    private final Parameters queryParams;
    private final Path path;
    private final Proxy proxy;
    private final String query;
    private final String fragment;
    private final int redirectionCount;

    ClientRequestImpl(ClientRequestBuilderImpl builder) {
        clientRequestHeaders = new ClientRequestHeadersImpl(builder.headers());
        requestMethod = builder.method();
        httpVersion = builder.httpVersion();
        uri = builder.uri();
        queryParams = new ReadOnlyParameters(builder.queryParams());
        query = builder.query();
        fragment = builder.fragment();
        //TODO path jak?
        path = null;
        requestConfiguration = builder.requestConfiguration();
        properties = new HashMap<>(builder.properties());
        proxy = builder.proxy();
        redirectionCount = builder.redirectionCount();
    }

    @Override
    public ClientRequestHeaders headers() {
        return clientRequestHeaders;
    }

    @Override
    public RequestConfiguration configuration() {
        return requestConfiguration;
    }

    @Override
    public Map<String, Object> properties() {
        return properties;
    }

    @Override
    public Proxy proxy() {
        return proxy;
    }

    @Override
    public int redirectionCount() {
        return redirectionCount;
    }

    @Override
    public Http.RequestMethod method() {
        return requestMethod;
    }

    @Override
    public Http.Version version() {
        return httpVersion;
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
