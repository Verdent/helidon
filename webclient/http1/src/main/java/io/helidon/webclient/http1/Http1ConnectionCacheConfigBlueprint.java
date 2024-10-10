package io.helidon.webclient.http1;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.common.concurrency.limits.Limit;
import io.helidon.common.concurrency.limits.spi.LimitProvider;

@Prototype.Configured
@Prototype.Blueprint
interface Http1ConnectionCacheConfigBlueprint {

    @Option.Provider(value = LimitProvider.class, discoverServices = false)
    @Option.Configured
    Optional<Limit> maxConnectionLimit();

    @Option.Provider(value = LimitProvider.class, discoverServices = false)
    @Option.Configured
    Optional<Limit> maxConnectionPerRouteLimit();

    @Option.Singular
    @Option.Configured
    Map<String, Limit> hostLimits();

    @Option.Singular
    @Option.Configured
    Map<String, Http1ProxyLimit> proxyLimits();

    @Option.Configured
    @Option.Default("PT5S")
    Duration keepAliveWaiting();

}
