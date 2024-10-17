package io.helidon.webclient.http1;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.common.concurrency.limits.Limit;
import io.helidon.common.concurrency.limits.spi.LimitProvider;

@Prototype.Configured
@Prototype.Blueprint
interface Http1ConnectionCacheConfigBlueprint {

    @Option.DefaultBoolean(true)
    @Option.Configured
    boolean enableConnectionLimits();

    @Option.Provider(value = LimitProvider.class, discoverServices = false)
    @Option.Configured
    Optional<Limit> connectionLimit();

    @Option.Provider(value = LimitProvider.class, discoverServices = false)
    @Option.Configured
    Optional<Limit> connectionPerRouteLimit();

    @Option.Provider(value = LimitProvider.class, discoverServices = false)
    @Option.Configured
    Optional<Limit> nonProxyConnectionLimit();

    @Option.Singular
    @Option.Configured
    List<HostLimitConfig> hostLimits();

    @Option.Singular
    @Option.Configured
    List<ProxyLimitConfig> proxyLimits();

    @Option.Configured
    @Option.Default("PT5S")
    Duration keepAliveWaiting();

}
