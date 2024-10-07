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

import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

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
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.spi.ClientConnectionCache;

import static java.lang.System.Logger.Level.DEBUG;

/**
 * Cache of HTTP/1.1 connections for keep alive.
 */
class Http1ConnectionCache extends ClientConnectionCache {
    private static final System.Logger LOGGER = System.getLogger(Http1ConnectionCache.class.getName());
    private static final Tls NO_TLS = Tls.builder().enabled(false).build();
    private static final String HTTPS = "https";
    private static final Http1ConnectionCache SHARED = new Http1ConnectionCache(Http1GlobalConfig.GLOBAL_CLIENT_CONFIG);;
    private static final List<String> ALPN_ID = List.of(Http1Client.PROTOCOL_ID);
    private static final Duration QUEUE_TIMEOUT = Duration.ofMillis(10);
    private final Limit maxConnectionLimit;
    private final Limit maxConnectionPerRouteLimit;
    private final Map<String, Limit> connectionLimitsPerHost = new ConcurrentHashMap<>();
    private final ConnectionCreationStrategy connectionCreationStrategy = new UnlimitedConnectionStrategy();
    private final Map<ConnectionKey, LinkedBlockingDeque<TcpClientConnection>> cache = new ConcurrentHashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean();

    private Http1ConnectionCache(boolean shared, Http1ClientConfig clientConfig) {
        super(shared);
        maxConnectionLimit = clientConfig.maxConnections().orElseGet(FixedLimit::create);
        maxConnectionPerRouteLimit = clientConfig.maxConnectionsPerRoute().orElseGet(FixedLimit::create);
    }

    private Http1ConnectionCache(Http1ClientConfig clientConfig) {
        this(false, clientConfig);
    }

    static Http1ConnectionCache shared() {
        return SHARED;
    }

    static Http1ConnectionCache create() {
        return new Http1ConnectionCache(false, Http1GlobalConfig.GLOBAL_CLIENT_CONFIG);
    }

    static Http1ConnectionCache create(Http1ClientConfig clientConfig) {
        return new Http1ConnectionCache(clientConfig);
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
            connection = createNewConnectionIfPossible(connectionKey, proxy, http1Client, connectionQueue);

            if (connection == null) {
                try {
                    while ((connection = connectionQueue.poll(5, TimeUnit.SECONDS)) != null && !connection.isConnected()) {
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

    private TcpClientConnection createNewConnectionIfPossible(ConnectionKey connectionKey, Proxy proxy,
                                                              Http1ClientImpl http1Client,
                                                              LinkedBlockingDeque<TcpClientConnection> connectionQueue) {

        //New connection should be created
        Optional<LimitAlgorithm.Token> maxConnectionToken = maxConnectionLimit.tryAcquire();
        if (maxConnectionToken.isPresent()) {
            //Maximum connections was not reached
            Optional<LimitAlgorithm.Token> maxProxyConnectionToken = proxy.maxConnections().tryAcquire();
            if (maxProxyConnectionToken.isPresent()) {
                //Maximum proxy connections was not reached
                Limit hostLimit = connectionLimitsPerHost.computeIfAbsent(connectionKey.host(),
                                                                          key -> proxy.maxPerHostConnections()
                                                                                  .orElse(maxConnectionPerRouteLimit).copy());
                Optional<LimitAlgorithm.Token> maxConnectionPerRouteLimitToken = hostLimit.tryAcquire();
                if (maxConnectionPerRouteLimitToken.isPresent()) {
                    //Maximum host connections was not reached
                    return TcpClientConnection.create(http1Client.webClient(),
                                                            connectionKey,
                                                            ALPN_ID,
                                                            conn -> finishRequest(connectionQueue, conn),
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
        } else {
            maxConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
        }
        return null;
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
        Optional<LimitAlgorithm.Token> maxConnectionToken = maxConnectionLimit.tryAcquire();
        Optional<LimitAlgorithm.Token> maxConnectionPerRouteLimitToken = maxConnectionPerRouteLimit.tryAcquire();

        if (maxConnectionToken.isEmpty() || maxConnectionPerRouteLimitToken.isEmpty()) {
            maxConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
            maxConnectionPerRouteLimitToken.ifPresent(LimitAlgorithm.Token::dropped);
            throw new IllegalStateException("Could not make a new HTTP connection. Maximum number of connections reached.");
        }

        WebClient webClient = http1Client.webClient();
        return TcpClientConnection.create(webClient,
                                          connectionKey,
                                          ALPN_ID,
                                          conn -> false, // always close connection
                                          conn -> {
                                              maxConnectionToken.get().success();
                                              maxConnectionPerRouteLimitToken.get().success();
                                          })
                .connect();
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
                                             LinkedBlockingDeque<TcpClientConnection> connectionQueue,
                                             Http1ConnectionCache cache);

    }

    private static final class UnlimitedConnectionStrategy implements ConnectionCreationStrategy {

        @Override
        public TcpClientConnection createConnection(ConnectionKey connectionKey,
                                                    Http1ClientImpl http1Client,
                                                    LinkedBlockingDeque<TcpClientConnection> connectionQueue,
                                                    Http1ConnectionCache cache) {
            return TcpClientConnection.create(http1Client.webClient(),
                                              connectionKey,
                                              ALPN_ID,
                                              conn -> cache.finishRequest(connectionQueue, conn),
                                              conn -> {})
                    .connect();
        }

    }

    private static final class ProxyLimitedConnectionStrategy implements ConnectionCreationStrategy {

        @Override
        public TcpClientConnection createConnection(ConnectionKey connectionKey,
                                                    Http1ClientImpl http1Client,
                                                    LinkedBlockingDeque<TcpClientConnection> connectionQueue,
                                                    Http1ConnectionCache cache) {
            Proxy proxy = connectionKey.proxy();
            //Maximum connections was not reached
            Optional<LimitAlgorithm.Token> maxProxyConnectionToken = proxy.maxConnections().tryAcquire();
            if (maxProxyConnectionToken.isPresent()) {
                //Maximum proxy connections was not reached
                Limit hostLimit = cache.connectionLimitsPerHost.computeIfAbsent(connectionKey.host(),
                                                                          key -> proxy.maxPerHostConnections()
                                                                                  .orElseGet(FixedLimit::create));
                Optional<LimitAlgorithm.Token> maxConnectionPerRouteLimitToken = hostLimit.tryAcquire();
                if (maxConnectionPerRouteLimitToken.isPresent()) {
                    //Maximum host connections was not reached
                    return TcpClientConnection.create(http1Client.webClient(),
                                                      connectionKey,
                                                      ALPN_ID,
                                                      conn -> cache.finishRequest(connectionQueue, conn),
                                                      conn -> {
                                                          maxProxyConnectionToken.get().success();
                                                          maxConnectionPerRouteLimitToken.get().success();
                                                      })
                            .connect();
                } else {
                    maxProxyConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
                    maxConnectionPerRouteLimitToken.ifPresent(LimitAlgorithm.Token::dropped);
                }
            } else {
                maxProxyConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
            }
            return null;
        }
    }

    private static final class FullyLimitedConnectionStrategy implements ConnectionCreationStrategy {

        @Override
        public TcpClientConnection createConnection(ConnectionKey connectionKey,
                                                    Http1ClientImpl http1Client,
                                                    LinkedBlockingDeque<TcpClientConnection> connectionQueue,
                                                    Http1ConnectionCache cache) {
            Proxy proxy = connectionKey.proxy();
            //Maximum connections was not reached
            //New connection should be created
            Optional<LimitAlgorithm.Token> maxConnectionToken = cache.maxConnectionLimit.tryAcquire();
            if (maxConnectionToken.isPresent()) {
                //Maximum connections was not reached
                Optional<LimitAlgorithm.Token> maxProxyConnectionToken = proxy.maxConnections().tryAcquire();
                if (maxProxyConnectionToken.isPresent()) {
                    //Maximum proxy connections was not reached
                    Limit hostLimit = cache.connectionLimitsPerHost.computeIfAbsent(connectionKey.host(),
                                                                              key -> proxy.maxPerHostConnections()
                                                                                      .orElse(cache.maxConnectionPerRouteLimit).copy());
                    Optional<LimitAlgorithm.Token> maxConnectionPerRouteLimitToken = hostLimit.tryAcquire();
                    if (maxConnectionPerRouteLimitToken.isPresent()) {
                        //Maximum host connections was not reached
                        return TcpClientConnection.create(http1Client.webClient(),
                                                          connectionKey,
                                                          ALPN_ID,
                                                          conn -> cache.finishRequest(connectionQueue, conn),
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
            } else {
                maxConnectionToken.ifPresent(LimitAlgorithm.Token::dropped);
            }
            return null;
        }
    }


}
