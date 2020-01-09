/*
 * Copyright (c) 2019, 2020 Oracle and/or its affiliates. All rights reserved.
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
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.net.ssl.SSLException;

import io.helidon.config.Config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

/**
 * Configuration of the Helidon web client.
 */
class ClientConfiguration {
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final LazyValue<String> userAgent;
    private final Proxy proxy;
    private final boolean followRedirects;
    private final int maxRedirects;
    private final ClientRequestHeaders clientHeaders;
    private final WebClientCookieManager cookieManager;
    private final CookiePolicy cookiePolicy;
    private final Ssl ssl;

    /**
     * Creates a new instance of client configuration.
     *
     * @param builder configuration builder
     */
    ClientConfiguration(Builder<?, ?> builder) {
        this.connectTimeout = builder.connectTimeout;
        this.readTimeout = builder.readTimeout;
        this.followRedirects = builder.followRedirects;
        this.userAgent = builder.userAgent;
        this.proxy = builder.proxy;
        this.ssl = builder.ssl;
        this.maxRedirects = builder.maxRedirects;
        this.clientHeaders = builder.clientHeaders;
        this.cookiePolicy = builder.cookiePolicy;
        this.cookieManager = WebClientCookieManager.create(builder.defaultCookies, builder.enableAutomaticCookieStore);
    }

    /**
     * Creates new builder to build a new instance of this class.
     *
     * @return a new builder instance
     */
    static Builder builder() {
        return new Builder();
    }

    /**
     * Derives a new builder based on current instance of this class.
     *
     * @return a new builder instance
     */
    Builder derive() {
        return new Builder().update(this);
    }

    Optional<SslContext> sslContext() {
        SslContext sslContext;
        try {
            //            KeyConfig.create().certs()
            //client private key (client ssl) ClientAuth. -> KeyManager
            SslContextBuilder sslContextBuilder = SslContextBuilder
                    .forClient()
                    .sslProvider(SslProvider.JDK)
                    .clientAuth(ssl.clientAuthentication());
            if (ssl.certificates().size() > 0) {
                sslContextBuilder.trustManager(ssl.certificates().toArray(new X509Certificate[0]));
            }
            if (ssl.clientPrivateKey() != null) {
                sslContextBuilder.keyManager(ssl.clientPrivateKey(),
                                             ssl.clientCertificateChain().toArray(new X509Certificate[0]));
            }

            if (ssl.trustAll()) {
                sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
            }

            sslContext = sslContextBuilder.build();
        } catch (SSLException e) {
            throw new ClientException("An error occurred while creating ssl context.", e);
        }
        return Optional.of(sslContext);
    }

    /**
     * Connection timeout duration.
     *
     * @return connection timeout
     */
    Duration connectTimeout() {
        return connectTimeout;
    }

    /**
     * Read timeout duration.
     *
     * @return read timeout
     */
    Duration readTimout() {
        return readTimeout;
    }

    /**
     * Configured proxy.
     *
     * @return proxy
     */
    public Optional<Proxy> proxy() {
        return Optional.ofNullable(proxy);
    }

    /**
     * Returns true if client should follow redirection.
     *
     * @return follow redirection
     */
    boolean followRedirects() {
        return followRedirects;
    }

    /**
     * Max number of followed redirections.
     *
     * @return max redirections
     */
    int maxRedirects() {
        return maxRedirects;
    }

    /**
     * Default client headers.
     *
     * @return default headers
     */
    ClientRequestHeaders headers() {
        return clientHeaders;
    }

    /**
     * Instance of {@link CookieManager}.
     *
     * @return cookie manager
     */
    CookieManager cookieManager() {
        return cookieManager;
    }

    /**
     * Returns user agent.
     *
     * @return user agent
     */
    public String userAgent() {
        return userAgent.get();
    }

    public Ssl ssl() {
        return ssl;
    }

    /**
     * A fluent API builder for {@link ClientConfiguration}.
     */
    static class Builder<B extends Builder<B, T>, T extends ClientConfiguration>
            implements io.helidon.common.Builder<T> {

        private final ClientRequestHeaders clientHeaders;

        private int maxRedirects;
        private Duration connectTimeout;
        private Duration readTimeout;
        private boolean followRedirects;
        private LazyValue<String> userAgent;
        private Proxy proxy;
        private boolean enableAutomaticCookieStore;
        private CookieStore cookieStore;
        private CookiePolicy cookiePolicy;
        private Ssl ssl;
        private Map<String, String> defaultCookies;
        private Set<OutboundTarget> outboundTargets;
        @SuppressWarnings("unchecked")
        private B me = (B) this;

        /**
         * Creates new instance of the builder.
         */
        Builder() {
            clientHeaders = new ClientRequestHeadersImpl();
            defaultCookies = new HashMap<>();
            outboundTargets = new HashSet<>();
        }

        @Override
        public T build() {
            return (T) new ClientConfiguration(this);
        }

        /**
         * Sets new connection timeout of the request.
         *
         * @param connectTimeout new connection timeout
         * @return updated builder instance
         */
        public B connectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
            return me;
        }

        /**
         * Sets new read timeout of the response.
         *
         * @param readTimeout new read timeout
         * @return updated builder instance
         */
        public B readTimeout(Duration readTimeout) {
            this.readTimeout = readTimeout;
            return me;
        }

        /**
         * Whether to follow any response redirections or not.
         *
         * @param followRedirects follow redirection
         * @return updated builder instance
         */
        public B followRedirects(boolean followRedirects) {
            this.followRedirects = followRedirects;
            return me;
        }

        /**
         * Sets new user agent of the request.
         *
         * @param userAgent user agent
         * @return updated builder instance
         */
        public B userAgent(String userAgent) {
            this.userAgent = LazyValue.create(() -> userAgent);
            return me;
        }

        /**
         * Sets new user agent wrapped by {@link LazyValue}.
         *
         * @param userAgent wrapped user agent
         * @return updated builder instance
         */
        public B userAgent(LazyValue<String> userAgent) {
            this.userAgent = userAgent;
            return me;
        }

        /**
         * Sets new request proxy.
         *
         * @param proxy request proxy
         * @return updated builder instance
         */
        public B proxy(Proxy proxy) {
            this.proxy = proxy;
            return me;
        }

        public B ssl(Ssl ssl) {
            this.ssl = ssl;
            return me;
        }

        /**
         * Sets max number of followed redirects.
         *
         * @param maxRedirects max redirects
         * @return updated builder instance
         */
        public B maxRedirects(int maxRedirects) {
            this.maxRedirects = maxRedirects;
            return me;
        }

        /**
         * Sets default client request headers.
         *
         * Overrides previously set default client headers.
         *
         * @param clientHeaders default request headers
         * @return updated builder instance
         */
        public B clientHeaders(ClientRequestHeaders clientHeaders) {
            this.clientHeaders.putAll(clientHeaders);
            return me;
        }

        /**
         * Sets new instance of {@link CookieStore} with default cookies.
         *
         * @param cookieStore cookie store
         * @return updated builder instance
         */
        public B cookieStore(CookieStore cookieStore) {
            this.cookieStore = cookieStore;
            return me;
        }

        /**
         * Sets new {@link CookiePolicy}.
         *
         * @param cookiePolicy cookie policy
         * @return updated builder instance
         */
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

        /**
         * Updates builder instance from the config.
         *
         * @param config config
         * @return updated builder instance
         */
        public B config(Config config) {
            // now for other options
            config.get("connect-timeout-millis").asLong().ifPresent(timeout -> connectTimeout(Duration.ofMillis(timeout)));
            config.get("read-timeout-millis").asLong().ifPresent(timeout -> readTimeout(Duration.ofMillis(timeout)));
            config.get("follow-redirects").asBoolean().ifPresent(this::followRedirects);
            config.get("max-redirects").asInt().ifPresent(this::maxRedirects);
            config.get("user-agent").asString().ifPresent(this::userAgent);
            config.get("cookies").asNode().ifPresent(this::cookies);
            config.get("headers").asNode().ifPresent(this::headers);
            config.get("ssl")
                    .as(Ssl.builder()::config)
                    .map(Ssl.Builder::build)
                    .ifPresent(this::ssl);
            config.get("proxy")
                    .as(Proxy.builder()::config)
                    .map(Proxy.Builder::build)
                    .ifPresent(this::proxy);

            //TODO targets s tomasem

            //            config.get("targets").asNodeList()
            //                    .ifPresent(configs -> configs.forEach(tarConf -> target(OutboundTarget.create(tarConf))));
            // TODO add all configurable options
            return me;
        }

        /**
         * Updates builder existing client configuration.
         *
         * @param configuration client configuration
         * @return updated builder instance
         */
        public B update(ClientConfiguration configuration) {
            connectTimeout(configuration.connectTimeout);
            readTimeout(configuration.readTimeout);
            followRedirects(configuration.followRedirects);
            userAgent(configuration.userAgent);
            proxy(configuration.proxy);
            ssl(configuration.ssl);
            maxRedirects(configuration.maxRedirects);
            clientHeaders(configuration.clientHeaders);
            cookieStore(configuration.cookieManager.getCookieStore());
            cookiePolicy(configuration.cookiePolicy);
            configuration.cookieManager.defaultCookies().forEach(this::defaultCookie);

            return me;
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
                            .forEach(header -> defaultCookie(header.get("name").asString().get(),
                                                             header.get("value").asString().get())));
        }
    }
}
