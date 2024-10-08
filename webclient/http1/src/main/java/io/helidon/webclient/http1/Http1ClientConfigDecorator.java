package io.helidon.webclient.http1;

import io.helidon.builder.api.Prototype;

class Http1ClientConfigDecorator implements Prototype.BuilderDecorator<Http1ClientConfig.BuilderBase<?, ?>> {

    @Override
    public void decorate(Http1ClientConfig.BuilderBase<?, ?> target) {
        if (target.enableConnectionLimit().isEmpty()) {
            boolean enable = target.maxConnectionLimit().isPresent() || target.maxConnectionsPerRouteLimit().isPresent();
            target.enableConnectionLimit(enable);
        }
    }

}
