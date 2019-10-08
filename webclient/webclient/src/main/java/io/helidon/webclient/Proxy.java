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

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import io.helidon.config.Config;

import io.netty.channel.ChannelHandler;

/**
 * A definition of a proxy server to use for outgoing requests.
 */
public interface Proxy {
    Proxy NO_PROXY = builder().build();

    /**
     * Fluent API builder for new instances.
     *
     * @return a new builder
     */
    static Builder builder() {
        return new Builder();
    }

    /**
     * A Proxy instance that does not proxy requests.
     *
     * @return a new instance with no proxy definition
     */
    static Proxy noProxy() {
        return NO_PROXY;
    }

    // we use netty everywhere - can we do this? Otherwise
    // we must do this in each component using netty
    Optional<ChannelHandler> handler(InetSocketAddress address);

    /**
     * Create a new proxy instance from configuration.
     * {@code
     * proxy:
     * http:
     * uri: https://www.example.org
     * https:
     * uri: https://www.example.org
     * no-proxy: ["*.example.org", "localhost"]
     * }
     *
     * @param config configuration, should be located on a key that has proxy as a subkey
     * @return
     */
    static Proxy create(Config config) {
        return Proxy.builder()
                .config(config)
                .build();
    }

    /**
     * Create from environment and system properties.
     *
     * @return a proxy instance configured based on this system settings
     */
    static Proxy create() {
        return Proxy.builder()
                .useSystemSelector(true)
                .build();
    }

    /**
     * Fluent API builder for {@link Proxy}.
     */
    class Builder implements io.helidon.common.Builder<Proxy> {
        private final Set<String> noProxyHosts = new HashSet<>();

        private ProxyType type;
        private String host;
        private int port = 80;
        private String username;
        private char[] password;
        private ProxySelector systemSelector;

        @Override
        public Proxy build() {
            if ((null == host) || (host.isEmpty() && (null == systemSelector))) {
                return NO_PROXY;
            }
            return new ProxyImpl(this);
        }

        public Builder config(Config config) {
            config.get("use-system-selector").asBoolean().ifPresent(this::useSystemSelector);
            if (this.type != ProxyType.SYSTEM) {
                config.get("type").asString().map(ProxyType::valueOf).ifPresent(this::type);
                config.get("host").asString().ifPresent(this::host);
                config.get("port").asInt().ifPresent(this::port);
                config.get("username").asString().ifPresent(this::username);
                config.get("password").asString().map(String::toCharArray).ifPresent(this::password);
                config.get("no-proxy").asList(String.class).ifPresent(hosts -> hosts.forEach(this::addNoProxy));
            }
            return this;
        }

        public Builder type(ProxyType type) {
            this.type = type;
            return this;
        }

        public Builder host(String host) {
            this.host = host;
            return this;
        }

        public Builder port(int port) {
            this.port = port;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder password(char[] password) {
            this.password = password;
            return this;
        }

        /**
         * Configure a host pattern that is not going through a proxy.
         * <p>
         * Options are:
         * <ul>
         *     <li>IP Address, such as {@code 192.168.1.1}</li>
         *     <li>IP V6 Address, such as {@code [2001:db8:85a3:8d3:1319:8a2e:370:7348]}</li>
         *     <li>Hostname, such as {@code localhost}</li>
         *     <li>Domain name, such as {@code helidon.io}</li>
         *     <li>Domain name and all sub-domains, such as {@code .helidon.io} (leading dot)</li>
         *     <li>Combination of all options from above with a port, such as {@code .helidon.io:80}</li>
         * </ul>
         *
         * @param noProxyHost to exclude from proxying
         * @return updated builder instance
         */
        public Builder addNoProxy(String noProxyHost) {
            noProxyHosts.add(noProxyHost);
            return this;
        }

        /**
         * Configure proxy from environment variables and system properties.
         *
         * @return updated builder instance
         */
        public Builder useSystemSelector(boolean useIt) {
            if (useIt) {
                this.type = ProxyType.SYSTEM;
                this.systemSelector = ProxySelector.getDefault();
            } else {
                if (this.type == ProxyType.SYSTEM) {
                    this.type = ProxyType.NONE;
                }
                this.systemSelector = null;
            }

            return this;
        }

        ProxyType type() {
            return type;
        }

        String host() {
            return host;
        }

        int port() {
            return port;
        }

        Set<String> noProxyHosts() {
            return new HashSet<>(noProxyHosts);
        }

        Optional<String> username() {
            return Optional.ofNullable(username);
        }

        Optional<char[]> password() {
            return Optional.ofNullable(password);
        }

        ProxySelector systemSelector() {
            return systemSelector;
        }
    }

    enum ProxyType {
        NONE,
        SYSTEM,
        HTTP,
        SOCKS_4,
        SOCKS_5
    }
}
