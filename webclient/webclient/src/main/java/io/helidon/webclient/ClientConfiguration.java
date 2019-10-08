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

import java.time.Duration;
import java.util.Optional;

import javax.net.ssl.HostnameVerifier;

import io.helidon.config.Config;

import io.netty.handler.ssl.SslContext;

/**
 * TODO javadoc.
 */
class ClientConfiguration {
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final boolean followRedirects;
    private final LazyValue<String> userAgent;
    private final Proxy proxy;
    private final boolean serverSslEnabled;
    private final boolean clientSslEnabled;
    private final HostnameVerifier hostnameVerifier;

    ClientConfiguration(Builder<?, ?> builder) {
        this.connectTimeout = builder.connectTimeout;
        this.readTimeout = builder.readTimeout;
        this.followRedirects = builder.followRedirects;
        this.userAgent = builder.userAgent;
        this.proxy = builder.proxy;
        this.serverSslEnabled = builder.serverSslEnabled;
        this.clientSslEnabled = builder.clientSslEnabled;
        this.hostnameVerifier = builder.hostnameVerifier;
    }

    static Builder builder() {
        return new Builder();
    }

    Builder derive() {
        return new Builder().update(this);
    }

    Optional<SslContext> sslContext() {
        if (!serverSslEnabled) {
            return Optional.empty();
        }

        // TODO implement
        return Optional.empty();
    }

    public Duration connectTimeout() {
        return connectTimeout;
    }

    public Duration readTimout() {
        return readTimeout;
    }

    public Optional<Proxy> proxy() {
        return Optional.ofNullable(proxy);
    }

    static class Builder<B extends Builder<B, T>, T extends ClientConfiguration>
            implements io.helidon.common.Builder<T> {

        private Duration connectTimeout;
        private Duration readTimeout;
        private boolean followRedirects;
        private LazyValue<String> userAgent;
        private Proxy proxy;
        private boolean serverSslEnabled;
        private boolean clientSslEnabled;
        private HostnameVerifier hostnameVerifier;
        @SuppressWarnings("unchecked")
        private B me = (B) this;

        Builder() {
        }

        @Override
        public T build() {
            return (T) new ClientConfiguration(this);
        }

        public B connectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
            return me;
        }

        public B readTimeout(Duration readTimeout) {
            this.readTimeout = readTimeout;
            return me;
        }

        public B followRedirects(boolean followRedirects) {
            this.followRedirects = followRedirects;
            return me;
        }

        public B userAgent(String userAgent) {
            this.userAgent = LazyValue.create(() -> userAgent);
            return me;
        }

        public B userAgent(LazyValue<String> userAgent) {
            this.userAgent = userAgent;
            return me;
        }

        public B proxy(Proxy proxy) {
            this.proxy = proxy;
            return me;
        }

        public B serverSslEnabled(boolean serverSslEnabled) {
            this.serverSslEnabled = serverSslEnabled;
            return me;
        }

        public B clientSslEnabled(boolean clientSslEnabled) {
            this.clientSslEnabled = clientSslEnabled;
            return me;
        }

        public B sslHostnameVerifier(HostnameVerifier hostnameVerifier) {
            this.hostnameVerifier = hostnameVerifier;
            return me;
        }

        public B config(Config config) {
            // now for other options
            config.get("connect-timeout-millis").asLong()
                    .ifPresent(timeout -> connectTimeout(Duration.ofMillis(timeout)));
            // TODO add all configurable options
            return me;
        }

        public B update(ClientConfiguration configuration) {
            connectTimeout(configuration.connectTimeout);
            readTimeout(configuration.readTimeout);
            followRedirects(configuration.followRedirects);
            userAgent(configuration.userAgent);
            proxy(configuration.proxy);
            serverSslEnabled(configuration.serverSslEnabled);
            clientSslEnabled(configuration.clientSslEnabled);
            sslHostnameVerifier(configuration.hostnameVerifier);

            return me;
        }
    }
}
