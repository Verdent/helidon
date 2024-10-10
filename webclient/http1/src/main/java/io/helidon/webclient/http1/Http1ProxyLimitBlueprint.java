package io.helidon.webclient.http1;

import java.util.Map;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.common.concurrency.limits.Limit;
import io.helidon.common.concurrency.limits.spi.LimitProvider;

@Prototype.Configured
@Prototype.Blueprint
interface Http1ProxyLimitBlueprint {

    @Option.Configured
    String host();

    @Option.Provider(value = LimitProvider.class, discoverServices = false)
    @Option.Configured
    Optional<Limit> maxConnectionLimit();

    @Option.Provider(value = LimitProvider.class, discoverServices = false)
    @Option.Configured
    Optional<Limit> maxConnectionPerRouteLimit();

    @Option.Singular("hostLimit")
    @Option.Configured
    Map<String, Limit> hostLimits();

}
