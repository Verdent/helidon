package io.helidon.webclient.http1;

import io.helidon.builder.api.Prototype;

class Http1ConnectionCacheConfigDecorator implements Prototype.BuilderDecorator<Http1ConnectionCacheConfig.BuilderBase<?, ?>> {

    @Override
    public void decorate(Http1ConnectionCacheConfig.BuilderBase<?, ?> target) {
        if (target.enableConnectionLimit().isEmpty()) {
            boolean enable = target.maxConnectionLimit().isPresent() || target.maxConnectionPerRouteLimit().isPresent();
            target.enableConnectionLimit(enable);
        }
    }

}
