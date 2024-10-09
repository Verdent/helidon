package io.helidon.webclient.http1;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.common.concurrency.limits.Limit;
import io.helidon.common.concurrency.limits.spi.LimitProvider;

@Prototype.Configured
@Prototype.Blueprint(decorator = Http1ConnectionCacheConfigDecorator.class)
interface Http1ConnectionCacheConfigBlueprint {

    @Option.Provider(value = LimitProvider.class, discoverServices = false)
    @Option.Configured
    Optional<Limit> maxConnectionLimit();

    @Option.Provider(value = LimitProvider.class, discoverServices = false)
    @Option.Configured
    Optional<Limit> maxConnectionPerRouteLimit();

    @Option.Configured
    Boolean enableConnectionLimit();

}
