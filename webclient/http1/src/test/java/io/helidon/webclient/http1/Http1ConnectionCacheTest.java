package io.helidon.webclient.http1;

import java.time.Duration;
import java.util.Optional;

import io.helidon.common.concurrency.limits.FixedLimit;
import io.helidon.common.concurrency.limits.Limit;
import io.helidon.common.uri.UriInfo;
import io.helidon.webclient.api.ConnectionKey;
import io.helidon.webclient.api.TcpClientConnection;
import io.helidon.webclient.api.WebClient;

import org.junit.jupiter.api.Test;

import static io.helidon.webclient.http1.Http1ConnectionCache.ConnectionCreationStrategy;
import static io.helidon.webclient.http1.Http1ConnectionCache.UnlimitedConnectionStrategy;
import static io.helidon.webclient.http1.Http1ConnectionCache.LimitedConnectionStrategy;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

class Http1ConnectionCacheTest {

    private static final Http1ClientImpl DEFAULT_CLIENT;

    static {
        WebClient webClient = WebClient.create();
        Http1ClientConfig clientConfig = Http1ClientConfig.create();
        DEFAULT_CLIENT = new Http1ClientImpl(webClient, clientConfig);
    }

    @Test
    void testDefaultConnectionCreationStrategyCreation() {
        Http1ConnectionCache cache = Http1ConnectionCache.create();
        assertThat(cache.strategy(), instanceOf(UnlimitedConnectionStrategy.class));
    }

    @Test
    void testLimitedConnectionCreationStrategyCreation() {
        Http1ConnectionCacheConfig connectionCacheConfig = Http1ConnectionCacheConfig.builder()
                .connectionLimit(FixedLimit.create())
                .build();
        Http1ConnectionCache cache = Http1ConnectionCache.create(connectionCacheConfig);
        assertThat(cache.strategy(), instanceOf(LimitedConnectionStrategy.class));
    }

    @Test
    void testDisabledLimits() {
        Http1ConnectionCacheConfig connectionCacheConfig = Http1ConnectionCacheConfig.builder()
                .connectionLimit(FixedLimit.create()) //This would indicate usage of the limited strategy
                .enableConnectionLimits(false) //This line enforces usage of unlimited strategy
                .build();
        Http1ConnectionCache cache = Http1ConnectionCache.create(connectionCacheConfig);
        assertThat(cache.strategy(), instanceOf(UnlimitedConnectionStrategy.class));
    }

    @Test
    void testUnlimitedConnectionStrategy() {
        Http1ClientRequest request = DEFAULT_CLIENT.get().uri("http://localhost:8080");
        Http1ClientConfig clientConfig = DEFAULT_CLIENT.prototype();
        UriInfo uri = request.resolvedUri();
        ConnectionKey connectionKey = new ConnectionKey(uri.scheme(),
                                                        uri.host(),
                                                        uri.port(),
                                                        clientConfig.readTimeout().orElse(Duration.ZERO),
                                                        clientConfig.tls(),
                                                        clientConfig.dnsResolver(),
                                                        clientConfig.dnsAddressLookup(),
                                                        clientConfig.proxy());
        ConnectionCreationStrategy strategy = new UnlimitedConnectionStrategy();

        for (int i = 0; i < 100; i++) {
            TcpClientConnection connection = strategy.createConnection(connectionKey,
                                                                       DEFAULT_CLIENT,
                                                                       tcpClientConnection -> false,
                                                                       true);
            assertThat(connection, notNullValue());
        }
    }


    @Test
    void testConnectionLimit() {
        Http1ConnectionCacheConfig cacheConfig = Http1ConnectionCacheConfig.builder()
                .connectionLimit(FixedLimit.builder().permits(5).build())
                .build();
        LimitedConnectionStrategy strategy = new LimitedConnectionStrategy(cacheConfig);
        testStrategyLimit("http://localhost:8080", strategy);
        assertThat(strategy.maxConnectionLimit().tryAcquire(false), is(Optional.empty()));

        assertThat(strategy.connectionLimitsPerHost().size(), is(1));
        Limit localhostLimit = strategy.connectionLimitsPerHost().get("localhost");
        assertThat(localhostLimit, notNullValue());
        assertThat(localhostLimit.tryAcquire(false), is(not((Optional.empty()))));
    }

    @Test
    void testPerHostConnectionLimit() {
        Http1ConnectionCacheConfig cacheConfig = Http1ConnectionCacheConfig.builder()
                .connectionPerRouteLimit(FixedLimit.builder().permits(5).build())
                .build();
        LimitedConnectionStrategy strategy = new LimitedConnectionStrategy(cacheConfig);
        testStrategyLimit("http://localhost:8080", strategy);
        assertThat(strategy.maxConnectionLimit().tryAcquire(false), is(not((Optional.empty()))));

        assertThat(strategy.connectionLimitsPerHost().size(), is(1));
        Limit localhostLimit = strategy.connectionLimitsPerHost().get("localhost");
        assertThat(localhostLimit, notNullValue());
        assertThat(localhostLimit.tryAcquire(false), is(Optional.empty()));

        testStrategyLimit("http://localhost2:8080", strategy);
    }

    private void testStrategyLimit(String uriString, LimitedConnectionStrategy strategy) {
        Http1ClientRequest request = DEFAULT_CLIENT.get().uri(uriString);
        Http1ClientConfig clientConfig = DEFAULT_CLIENT.prototype();
        UriInfo uri = request.resolvedUri();
        ConnectionKey connectionKey = new ConnectionKey(uri.scheme(),
                                                        uri.host(),
                                                        uri.port(),
                                                        clientConfig.readTimeout().orElse(Duration.ZERO),
                                                        clientConfig.tls(),
                                                        clientConfig.dnsResolver(),
                                                        clientConfig.dnsAddressLookup(),
                                                        clientConfig.proxy());
        for (int i = 1; i <= 6; i++) {
            TcpClientConnection connection = strategy.createConnection(connectionKey,
                                                                       DEFAULT_CLIENT,
                                                                       tcpClientConnection -> true,
                                                                       true);
            if (i <= 5) {
                assertThat(connection, notNullValue());
            } else {
                assertThat(connection, nullValue());
            }
        }
    }

}
