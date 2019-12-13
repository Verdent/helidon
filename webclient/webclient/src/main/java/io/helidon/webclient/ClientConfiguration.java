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

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.CookieStore;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;

import io.helidon.config.Config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;

/**
 * TODO javadoc.
 */
class ClientConfiguration {
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final LazyValue<String> userAgent;
    private final Proxy proxy;
    private final boolean followRedirects;
    private final boolean serverSslEnabled;
    private final boolean clientSslEnabled;
    private final HostnameVerifier hostnameVerifier;
    private final int maxRedirects;
    private final ClientRequestHeaders clientHeaders;
    private final WebClientCookieManager cookieManager;
    private final CookiePolicy cookiePolicy;

    ClientConfiguration(Builder<?, ?> builder) {
        this.connectTimeout = builder.connectTimeout;
        this.readTimeout = builder.readTimeout;
        this.followRedirects = builder.followRedirects;
        this.userAgent = builder.userAgent;
        this.proxy = builder.proxy;
        this.serverSslEnabled = builder.serverSslEnabled;
        this.clientSslEnabled = builder.clientSslEnabled;
        this.hostnameVerifier = builder.hostnameVerifier;
        this.maxRedirects = builder.maxRedirects;
        this.clientHeaders = builder.clientHeaders;
        this.cookiePolicy = builder.cookiePolicy;
        this.cookieManager = WebClientCookieManager.create(builder.defaultCookies, builder.enableAutomaticCookieStore);
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
        SslContext sslContext;
        try {
            sslContext = SslContextBuilder
                    .forClient()
                    //.sslProvider(SslProvider.JDK)
                    .build();
        } catch (SSLException e) {
            throw new ClientException("An error occurred while creating ssl context.", e);
        }
        return Optional.of(sslContext);
    }

    Duration connectTimeout() {
        return connectTimeout;
    }

    Duration readTimout() {
        return readTimeout;
    }

    public Optional<Proxy> proxy() {
        return Optional.ofNullable(proxy);
    }

    boolean followRedirects() {
        return followRedirects;
    }

    int maxRedirects() {
        return maxRedirects;
    }

    ClientRequestHeaders headers() {
        return clientHeaders;
    }

    CookieManager cookieManager() {
        return cookieManager;
    }

    public boolean clientSslEnabled() {
        return clientSslEnabled;
    }

    static class Builder<B extends Builder<B, T>, T extends ClientConfiguration>
            implements io.helidon.common.Builder<T> {

        private final ClientRequestHeaders clientHeaders;

        private int maxRedirects;
        private Duration connectTimeout;
        private Duration readTimeout;
        private boolean followRedirects;
        private LazyValue<String> userAgent;
        private Proxy proxy;
        private boolean serverSslEnabled;
        private boolean clientSslEnabled;
        private HostnameVerifier hostnameVerifier;
        private boolean enableAutomaticCookieStore;
        private CookieStore cookieStore;
        private CookiePolicy cookiePolicy;
        private Map<String, String> defaultCookies;
        private Set<OutboundTarget> outboundTargets;
        @SuppressWarnings("unchecked")
        private B me = (B) this;

        Builder() {
            clientHeaders = new ClientRequestHeadersImpl();
            defaultCookies = new HashMap<>();
            outboundTargets = new HashSet<>();
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

        public B maxRedirects(int maxRedirects) {
            this.maxRedirects = maxRedirects;
            return me;
        }

        public B clientHeaders(ClientRequestHeaders clientHeaders) {
            this.clientHeaders.putAll(clientHeaders);
            return me;
        }

        public B cookieStore(CookieStore cookieStore) {
            this.cookieStore = cookieStore;
            return me;
        }

        public B cookiePolicy(CookiePolicy cookiePolicy) {
            this.cookiePolicy = cookiePolicy;
            return me;
        }

        private B enableAutomaticCookieStore(Boolean enableAutomaticCookieStore) {
            this.enableAutomaticCookieStore = enableAutomaticCookieStore;
            return me;
        }

        private B defaultCookie(String key, String value) {
            defaultCookies.put(key, value);
            return me;
        }

        private B target(OutboundTarget target) {
            return me;
        }

        public B config(Config config) {
            // now for other options
            config.get("connect-timeout-millis").asLong().ifPresent(timeout -> connectTimeout(Duration.ofMillis(timeout)));
            config.get("read-timeout-millis").asLong().ifPresent(timeout -> readTimeout(Duration.ofMillis(timeout)));
            config.get("follow-redirects").asBoolean().ifPresent(this::followRedirects);
            config.get("max-redirects").asInt().ifPresent(this::maxRedirects);
            config.get("user-agent").asString().ifPresent(this::userAgent);
            ssl(config.get("ssl"));
            cookies(config.get("cookies"));
            headers(config.get("headers"));
            proxy(Proxy.builder().config(config.get("proxy")).build());
            config.get("targets").asNodeList()
                    .ifPresent(configs -> configs.forEach(tarConf -> target(OutboundTarget.create(tarConf))));
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
            maxRedirects(configuration.maxRedirects);
            clientHeaders(configuration.clientHeaders);
            cookieStore(configuration.cookieManager.getCookieStore());
            cookiePolicy(configuration.cookiePolicy);
            configuration.cookieManager.defaultCookies().forEach(this::defaultCookie);

            return me;
        }

        private void ssl(Config ssl) {
            ssl.get("enabled").asBoolean().ifPresent(this::clientSslEnabled);
            //TODO next parts of ssl
        }

        private void headers(Config configHeaders) {
            configHeaders.asNodeList()
                    .ifPresent(headers -> headers
                            .forEach(header -> clientHeaders.put(header.get("name").asString().get(),
                                                                 header.get("value").asList(String.class).get())));
        }

        private void cookies(Config cookies) {
            cookies.get("automatic-store-enabled").asBoolean().ifPresent(this::enableAutomaticCookieStore);
            Config map = cookies.get("default-cookies");
            map.asNodeList()
                    .ifPresent(headers -> headers
                            .forEach(header -> defaultCookies.put(header.get("name").asString().get(),
                                                                  header.get("value").asString().get())));
        }
    }
}
