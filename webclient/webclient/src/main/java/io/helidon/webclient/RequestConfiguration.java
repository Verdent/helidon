/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import io.helidon.common.GenericType;
import io.helidon.media.common.MessageBodyReader;
import io.helidon.webclient.spi.ClientService;

/**
 * TODO javadoc.
 */
class RequestConfiguration extends ClientConfiguration {

    private final URI requestURI;
    private final ClientServiceRequest clientServiceRequest;
    private final List<ClientService> services;

    private RequestConfiguration(Builder builder) {
        super(builder);
        requestURI = builder.requestURI;
        clientServiceRequest = builder.clientServiceRequest;
        services = builder.services;
    }

    public URI requestURI() {
        return requestURI;
    }

    public ClientServiceRequest clientServiceRequest() {
        return clientServiceRequest;
    }

    public List<ClientService> services() {
        return services;
    }

    static Builder builder(URI requestURI) {
        return new Builder(requestURI);
    }

    static class Builder extends ClientConfiguration.Builder<Builder, RequestConfiguration> {

        private ClientServiceRequest clientServiceRequest;
        private URI requestURI;
        private List<ClientService> services = new ArrayList<>();

        public Builder(URI requestURI) {
            this.requestURI = requestURI;
        }

        public Builder clientServiceRequest(ClientServiceRequest clientServiceRequest) {
            this.clientServiceRequest = clientServiceRequest;
            return this;
        }

        public Builder services(List<ClientService> services) {
            this.services = Collections.unmodifiableList(services);
            return this;
        }

        @Override
        public RequestConfiguration build() {
            return new RequestConfiguration(this);
        }


    }
}
