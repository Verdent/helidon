/*
 * Copyright (c) 2023 Oracle and/or its affiliates.
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

package io.helidon.webclient.http1;

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.stream.Collectors;

import io.helidon.common.concurrency.limits.FixedLimit;
import io.helidon.common.concurrency.limits.Limit;
import io.helidon.common.concurrency.limits.LimitAlgorithm;
import io.helidon.common.tls.Tls;
import io.helidon.http.ClientRequestHeaders;
import io.helidon.http.HeaderValues;
import io.helidon.http.WritableHeaders;
import io.helidon.webclient.api.ClientConnection;
import io.helidon.webclient.api.ClientUri;
import io.helidon.webclient.api.ConnectionKey;
import io.helidon.webclient.api.Proxy;
import io.helidon.webclient.api.TcpClientConnection;
import io.helidon.webclient.spi.ClientConnectionCache;

import static java.lang.System.Logger.Level.DEBUG;

/**
 * Cache of HTTP/1.1 connections for keep alive.
 */
class Http1ConnectionCache extends ClientConnectionCache {
    private static final System.Logger LOGGER = System.getLogger(Http1ConnectionCache.class.getName());
    private static final Tls NO_TLS = Tls.builder().enabled(false).build();
    private static final String HTTPS = "https";
    private static final ConnectionCreationStrategy UNLIMITED_STRATEGY = new UnlimitedConnectionStrategy();
    private static final List<String> ALPN_ID = List.of(Http1Client.PROTOCOL_ID);
    private static final Duration QUEUE_TIMEOUT = Duration.ofMillis(10);
    private static final Http1ConnectionCacheConfig EMPTY_CONFIG = Http1ConnectionCacheConfig.create();
    private static final Http1ConnectionCache SHARED = new Http1ConnectionCache(true,
                                                                                Http1ClientImpl.globalConfig().connectionCache());
    private final ConnectionCreationStrategy connectionCreationStrategy;
    private final Duration keepAliveWaiting;
    private final Map<ConnectionKey, LinkedBlockingDeque<TcpClientConnection>> cache = new ConcurrentHashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean();

    private Http1ConnectionCache(boolean shared, Http1ConnectionCacheConfig cacheConfig) {
        super(shared);
        if (cacheConfig.enableConnectionLimits()) {
            if (cacheConfig.maxConnectionLimit().isPresent()
                    || cacheConfig.maxConnectionPerRouteLimit().isPresent()
                    || !cacheConfig.hostLimits().isEmpty()
                    || !cacheConfig.proxyLimits().isEmpty()) {
                connectionCreationStrategy = new LimitedConnectionStrategy(cacheConfig);
            } else {
                connectionCreationStrategy = UNLIMITED_STRATEGY;
            }
        } else {
            connectionCreationStrategy = UNLIMITED_STRATEGY;
        }
        keepAliveWaiting = cacheConfig.keepAliveWaiting();
    }

    private Http1ConnectionCache(Http1ConnectionCacheConfig clientConfig) {
        this(false, clientConfig);
    }

    static Http1ConnectionCache shared() {
        return SHARED;
    }

    static Http1ConnectionCache create() {
        return new Http1ConnectionCache(EMPTY_CONFIG);
    }

    static Http1ConnectionCache create(Http1ConnectionCacheConfig cacheConfig) {
        return new Http1ConnectionCache(cacheConfig);
    }

    ClientConnection connection(Http1ClientImpl http1Client,
                                Duration requestReadTimeout,
                                Tls tls,
                                Proxy proxy,
                                ClientUri uri,
                                ClientRequestHeaders headers,
                                boolean defaultKeepAlive) {
        boolean keepAlive = handleKeepAlive(defaultKeepAlive, headers);
        Tls effectiveTls = HTTPS.equals(uri.scheme()) ? tls : NO_TLS;
        if (keepAlive) {
            return keepAliveConnection(http1Client, requestReadTimeout, effectiveTls, uri, proxy);
        } else {
            return oneOffConnection(http1Client, effectiveTls, uri, proxy);
        }
    }

    @Override
    public void closeResource() {
        if (closed.getAndSet(true)) {
            return;
        }
        cache.values().stream()
                .flatMap(Collection::stream)
                .forEach(TcpClientConnection::closeResource);
    }

    private boolean handleKeepAlive(boolean defaultKeepAlive, WritableHeaders<?> headers) {
        if (headers.contains(HeaderValues.CONNECTION_CLOSE)) {
            return false;
        }
        if (defaultKeepAlive) {
            headers.setIfAbsent(HeaderValues.CONNECTION_KEEP_ALIVE);
            return true;
        }
        if (headers.contains(HeaderValues.CONNECTION_KEEP_ALIVE)) {
            return true;
        }
        headers.set(HeaderValues.CONNECTION_CLOSE);
        return false;
    }

    private ClientConnection keepAliveConnection(Http1ClientImpl http1Client,
                                                 Duration requestReadTimeout,
                                                 Tls tls,
                                                 ClientUri uri,
                                                 Proxy proxy) {

        if (closed.get()) {
            throw new IllegalStateException("Connection cache is closed");
        }

        Http1ClientConfig clientConfig = http1Client.clientConfig();

        ConnectionKey connectionKey = new ConnectionKey(uri.scheme(),
                                                        uri.host(),
                                                        uri.port(),
                                                        clientConfig.readTimeout().orElse(requestReadTimeout),
                                                        tls,
                                                        clientConfig.dnsResolver(),
                                                        clientConfig.dnsAddressLookup(),
                                                        proxy);

        LinkedBlockingDeque<TcpClientConnection> connectionQueue =
                cache.computeIfAbsent(connectionKey,
                                      it -> new LinkedBlockingDeque<>(clientConfig.connectionCacheSize()));

        TcpClientConnection connection;
        while ((connection = connectionQueue.poll()) != null && !connection.isConnected()) {
        }

        if (connection == null) {
            connection = connectionCreationStrategy.createConnection(connectionKey,
                                                                     http1Client,
                                                                     conn -> finishRequest(connectionQueue, conn),
                                                                     this,
                                                                     true);
            if (connection == null) {
                try {
                    while ((connection = connectionQueue.poll(keepAliveWaiting.toMillis(), TimeUnit.MILLISECONDS)) != null
                            && !connection.isConnected()) {
                    }
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                if (connection == null) {
                    throw new IllegalStateException("Could not make a new HTTP connection. Maximum number of connections reached.");
                } else {
                    if (LOGGER.isLoggable(DEBUG)) {
                        LOGGER.log(DEBUG, String.format("[%s] client connection obtained %s",
                                                        connection.channelId(),
                                                        Thread.currentThread().getName()));
                    }
                }
            }
        } else {
            if (LOGGER.isLoggable(DEBUG)) {
                LOGGER.log(DEBUG, String.format("[%s] client connection obtained %s",
                                                connection.channelId(),
                                                Thread.currentThread().getName()));
            }
        }
        return connection;
    }

    private ClientConnection oneOffConnection(Http1ClientImpl http1Client,
                                              Tls tls,
                                              ClientUri uri,
                                              Proxy proxy) {
        Http1ClientConfig clientConfig = http1Client.clientConfig();
        ConnectionKey connectionKey = new ConnectionKey(uri.scheme(),
                                                        uri.host(),
                                                        uri.port(),
                                                        clientConfig.readTimeout().orElse(Duration.ZERO),
                                                        tls,
                                                        clientConfig.dnsResolver(),
                                                        clientConfig.dnsAddressLookup(),
                                                        proxy);

        TcpClientConnection connection = connectionCreationStrategy.createConnection(connectionKey,
                                                                                     http1Client,
                                                                                     conn -> false,
                                                                                     this,
                                                                                     false);

        if (connection == null) {
            throw new IllegalStateException("Could not make a new HTTP connection. Maximum number of connections reached.");
        }

        return connection;
    }

    private boolean finishRequest(LinkedBlockingDeque<TcpClientConnection> connectionQueue, TcpClientConnection conn) {
        if (conn.isConnected()) {
            try {
                conn.helidonSocket().idle(); // mark it as idle to stay blocked at read for closed conn detection
                if (connectionQueue.offer(conn, QUEUE_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                    if (LOGGER.isLoggable(DEBUG)) {
                        LOGGER.log(DEBUG, "[%s] client connection returned %s",
                                   conn.channelId(),
                                   Thread.currentThread().getName());
                    }
                    return true;
                } else {
                    if (LOGGER.isLoggable(DEBUG)) {
                        LOGGER.log(DEBUG, "[%s] Unable to return client connection because queue is full %s",
                                   conn.channelId(),
                                   Thread.currentThread().getName());
                    }
                }
            } catch (InterruptedException e) {
                if (LOGGER.isLoggable(DEBUG)) {
                    LOGGER.log(DEBUG, "[%s] Unable to return client connection due to '%s' %s",
                               conn.channelId(),
                               e.getMessage(),
                               Thread.currentThread().getName());
                }
            }
        }
        return false;
    }

    private interface ConnectionCreationStrategy {

        TcpClientConnection createConnection(ConnectionKey connectionKey,
                                             Http1ClientImpl http1Client,
                                             Function<TcpClientConnection, Boolean> releaseFunction,
                                             Http1ConnectionCache cache,
                                             boolean keepAlive);

    }

    private static final class UnlimitedConnectionStrategy implements ConnectionCreationStrategy {

        @Override
        public TcpClientConnection createConnection(ConnectionKey connectionKey,
                                                    Http1ClientImpl http1Client,
                                                    Function<TcpClientConnection, Boolean> releaseFunction,
                                                    Http1ConnectionCache cache,
                                                    boolean keepAlive) {
            return TcpClientConnection.create(http1Client.webClient(),
                                              connectionKey,
                                              ALPN_ID,
                                              releaseFunction,
                                              conn -> {})
                    .connect();
        }

    }

    private static class LimitedConnectionStrategy implements ConnectionCreationStrategy {

        private static final Limit NOOP = FixedLimit.create();
        private static final Optional<LimitAlgorithm.Token> NOOP_TOKEN = NOOP.tryAcquire();

        private final Lock hostsConnectionLimitLock = new ReentrantLock();
        private final Limit maxConnectionLimit;
        private final Limit maxConnectionPerRouteLimit;
        private final Map<String, ProxyLimitConfig> proxyConfigs;
        private final Map<String, Limit> proxyConnectionLimits;
        private final Map<String, Limit> connectionLimitsPerHost = new HashMap<>();

        public LimitedConnectionStrategy(Http1ConnectionCacheConfig cacheConfig) {
            maxConnectionLimit = cacheConfig.maxConnectionLimit().orElse(NOOP).copy();
            maxConnectionPerRouteLimit = cacheConfig.maxConnectionPerRouteLimit().orElse(NOOP).copy();
            for (HostLimitConfig hostLimit : cacheConfig.hostLimits()) {
                String key = hostLimit.host() + "|";
                connectionLimitsPerHost.put(key, hostLimit.limit().copy());
            }
            Map<String, Limit> proxyConnectionLimits = new HashMap<>();
            for (ProxyLimitConfig proxyLimit : cacheConfig.proxyLimits()) {
                proxyLimit.maxConnectionLimit().ifPresent(it -> proxyConnectionLimits.put(proxyLimit.proxy(), it.copy()));
                for (HostLimitConfig hostLimit : proxyLimit.hostLimits()) {
                    String key = hostLimit.host() + "|" + proxyLimit.proxy();
                    connectionLimitsPerHost.put(key, hostLimit.limit().copy());
                }
            }
            this.proxyConnectionLimits = Map.copyOf(proxyConnectionLimits);
            this.proxyConfigs = cacheConfig.proxyLimits().stream().collect(Collectors.toMap(ProxyLimitConfig::proxy,
                                                                                            Function.identity()));
        }

        @Override
        public TcpClientConnection createConnection(ConnectionKey connectionKey,
                                                    Http1ClientImpl http1Client,
                                                    Function<TcpClientConnection, Boolean> releaseFunction,
                                                    Http1ConnectionCache cache,
                                                    boolean keepAlive) {
            //Maximum connections was not reached
            //New connection should be created
            Optional<LimitAlgorithm.Token> maxConnectionToken = maxConnectionLimit.tryAcquire(!keepAlive);
            if (maxConnectionToken.isPresent()) {
                //Maximum connections was not reached
                Proxy proxy = connectionKey.proxy();
                Optional<LimitAlgorithm.Token> maxProxyConnectionToken;
                String proxyIdent;
                if (proxy.type() == Proxy.ProxyType.NONE) {
                    maxProxyConnectionToken = NOOP_TOKEN;
                    proxyIdent = "";
                } else if (proxy.type() == Proxy.ProxyType.SYSTEM) {
                    String scheme = connectionKey.tls().enabled() ? "https" : "http";
                    ProxySelector proxySelector = ProxySelector.getDefault();
                    if (proxySelector == null) {
                        maxProxyConnectionToken = NOOP_TOKEN;
                        proxyIdent = "";
                    } else {
                        List<java.net.Proxy> proxies = proxySelector
                                .select(URI.create(scheme + "://" + connectionKey.host() + ":" + connectionKey.port()));
                        if (proxies.isEmpty()) {
                            maxProxyConnectionToken = NOOP_TOKEN;
                            proxyIdent = "";
                        } else {
                            java.net.Proxy jnProxy = proxies.getFirst();
                            if (jnProxy.type() == java.net.Proxy.Type.DIRECT) {
                                maxProxyConnectionToken = NOOP_TOKEN;
                                proxyIdent = "";
                            } else {
                                SocketAddress proxyAddress = jnProxy.address();
                                if (proxyAddress instanceof InetSocketAddress inetSocketAddress) {
                                    proxyIdent = inetSocketAddress.getHostName() + ":" + inetSocketAddress.getPort();
                                } else {
                                    proxyIdent = proxyAddress.toString();
                                }
                                Limit proxyConnectionLimit = proxyConnectionLimits.getOrDefault(proxyIdent, NOOP);
                                maxProxyConnectionToken = proxyConnectionLimit.tryAcquire(!keepAlive);
                            }
                        }
                    }
                } else {
                    proxyIdent = proxy.host() + ":" + proxy.port();
                    Limit proxyConnectionLimit = proxyConnectionLimits.getOrDefault(proxyIdent, NOOP);
                    maxProxyConnectionToken = proxyConnectionLimit.tryAcquire(!keepAlive);
                }
                if (maxProxyConnectionToken.isPresent()) {
                    //Maximum proxy connections was not reached
                    String hostKey = connectionKey.host() + "|" + proxyIdent;
                    Limit hostLimit;
                    try {
                        hostsConnectionLimitLock.lock();
                        hostLimit = connectionLimitsPerHost.computeIfAbsent(hostKey,
                                                                            key -> Optional.ofNullable(proxyConfigs.get(proxyIdent))
                                                                                    .flatMap(ProxyLimitConfigBlueprint::maxConnectionPerRouteLimit)
                                                                                    .orElse(maxConnectionPerRouteLimit)
                                                                                    .copy());
                    } finally {
                        hostsConnectionLimitLock.unlock();
                    }
                    Optional<LimitAlgorithm.Token> maxConnectionPerRouteLimitToken = hostLimit.tryAcquire(!keepAlive);
                    if (maxConnectionPerRouteLimitToken.isPresent()) {
                        //Maximum host connections was not reached
                        return TcpClientConnection.create(http1Client.webClient(),
                                                          connectionKey,
                                                          ALPN_ID,
                                                          releaseFunction,
                                                          conn -> {
                                                              maxConnectionToken.get().success();
                                                              maxProxyConnectionToken.get().success();
                                                              maxConnectionPerRouteLimitToken.get().success();
                                                          })
                                .connect();
                    } else {
                        maxConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
                        maxProxyConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
                        maxConnectionPerRouteLimitToken.ifPresent(LimitAlgorithm.Token::dropped);
                    }
                } else {
                    maxConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
                    maxProxyConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
                }
                maxConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
            }
            return null;
        }
    }

}
