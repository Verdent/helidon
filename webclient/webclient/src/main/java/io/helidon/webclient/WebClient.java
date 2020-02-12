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
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Duration;
import java.time.temporal.TemporalUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;
import java.util.stream.Collectors;

import io.helidon.common.context.Context;
import io.helidon.common.serviceloader.HelidonServiceLoader;
import io.helidon.config.Config;
import io.helidon.media.common.MediaSupport;
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

    //EDIT: projit builder a dodelat implementace fieldu
    final class Builder implements io.helidon.common.Builder<WebClient> {
        private final ClientConfiguration.Builder configuration = NettyClient.SHARED_CONFIGURATION.get().derive();

        private Builder() {
        }

        @Override
        public WebClient build() {
            return new NettyClient(this);
        }

        public Builder register(ClientService service) {
            configuration.clientServiceProvider(new ClientServiceProvider() {
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

        public Builder mediaSupport(MediaSupport mediaSupport) {
            configuration.mediaSupport(mediaSupport);
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

        /**
         * Sets specific context which should be used in requests.
         *
         * @param context context
         * @return updated builder instance
         */
        public Builder context(Context context) {
            configuration.context(context);
            return this;
        }

        /**
         * Add a default cookie.
         *
         * @param name cookie name
         * @param value cookie value
         * @return
         */
        public Builder addCookie(String name, String value) {
            configuration.defaultCookie(name, value);
            return this;
        }

        /**
         * Add a default header (such as accept)
         *
         * @param header header name
         * @param value header values
         * @return
         */
        public Builder addHeader(String header, String... value) {
            configuration.defaultHeader(header, Arrays.asList(value));
            return this;
        }

        public Builder baseUri(URI uri) {
            configuration.uri(uri);
            return this;
        }

        public Builder baseUri(String uri) {
            return baseUri(URI.create(uri));
        }

        public Builder baseUri(URL url) {
            try {
                return baseUri(url.toURI());
            } catch (URISyntaxException e) {
                throw new ClientException("Failed to create URI from URL", e);
            }
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

    }
}
