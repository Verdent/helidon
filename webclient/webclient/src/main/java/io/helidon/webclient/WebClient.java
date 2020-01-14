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
import java.time.Duration;
import java.time.temporal.TemporalUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;
import java.util.stream.Collectors;

import io.helidon.common.serviceloader.HelidonServiceLoader;
import io.helidon.config.Config;
import io.helidon.webclient.spi.ClientService;
import io.helidon.webclient.spi.ClientServiceProvider;

/**
 *
 */
public interface WebClient {

    /**
     * Create a new rest client.
     *
     * @return client
     */
    static WebClient create() {
        return builder().build();
    }

    /**
     * Fluent API builder for client.
     *
     * @return client builder
     */
    static Builder builder() {
        return new Builder();
    }

    /**
     * Create a request builder for a put method.
     *
     * @return client request builder
     */
    ClientRequestBuilder put();

    /**
     * Create a request builder for a get method.
     *
     * @return client request builder
     */
    ClientRequestBuilder get();

    /**
     * Create a request builder for a method based on method parameter.
     *
     * @param method request method
     * @return client request builder
     */
    ClientRequestBuilder method(String method);

    final class Builder implements io.helidon.common.Builder<WebClient> {
        private final ClientConfiguration.Builder configuration = NettyClient.SHARED_CONFIGURATION.get().derive();

        private HelidonServiceLoader.Builder<ClientServiceProvider> services = HelidonServiceLoader
                .builder(ServiceLoader.load(ClientServiceProvider.class));
        private List<ClientContentHandler<?>> clientContentHandlers = new ArrayList<>();

        private Builder() {
        }

        @Override
        public WebClient build() {
            return new NettyClient(this);
        }

        public Builder register(ClientService service) {
            //EDIT: pro svou zajimavost prozkoumat JavaServiceLoader
            services.addService(new ClientServiceProvider() {
                @Override
                public String configKey() {
                    return "ignored";
                }

                @Override
                public ClientService create(Config config) {
                    return service;
                }
            });
            return this;
        }

        public Builder proxy(Proxy proxy) {
            this.configuration.proxy(proxy);
            return this;
        }

        public Builder register(ClientContentHandler<?> contentHandler) {
            clientContentHandlers.add(contentHandler);
            return this;
        }

        public Builder config(Config config) {
            configuration.config(config);
            return this;
        }

        public Builder connectTimeout(long amount, TemporalUnit unit) {
            configuration.connectTimeout(Duration.of(amount, unit));
            return this;
        }

        public Builder readTimeout(long amount, TemporalUnit unit) {
            configuration.readTimeout(Duration.of(amount, unit));
            return this;
        }

        public Builder ssl(Ssl ssl) {
            configuration.ssl(ssl);
            return this;
        }

        public Builder addTarget(OutboundTarget target) {
            return this;
        }

        /**
         * Add a default cookie.
         *
         * @param name
         * @param value
         * @return
         */
        public Builder addCookie(String name, String value) {
            return this;
        }

        /**
         * Add a default header (such as accept)
         *
         * @param header
         * @param value
         * @return
         */
        public Builder addHeader(String header, String... value) {
            return this;
        }

        public Builder baseUri(URI uri) {
            return this;
        }

        public Builder baseUri(String uri) {
            return this;
        }

        public Builder baseUri(URL url) {
            return this;
        }

        public Builder followRedirects(boolean follow) {
            configuration.followRedirects(follow);
            return this;
        }

        public Builder userAgent(String userAgent) {
            configuration.userAgent(userAgent);
            return this;
        }

        public ClientConfiguration configuration() {
            return configuration.build();
        }

        //EDIT: premistit do clientconfigurace
        public List<ClientService> services() {
            //EDIT: dodelat config
            Config config = this.configuration == null ? Config.empty() : this.configuration.config();
            Config servicesConfig = config.get("services");
            servicesConfig.get("excludes").asList(String.class).orElse(Collections.emptyList())
                    .forEach(services::addExcludedClassName);

            Config serviceConfig = servicesConfig.get("config");

            return services.build()
                    .asList()
                    .stream()
                    .map(it -> it.create(serviceConfig.get(it.configKey())))
                    .collect(Collectors.toList());
        }

        public List<ClientContentHandler<?>> clientContentHandlers() {
            return clientContentHandlers;
        }
    }
}
