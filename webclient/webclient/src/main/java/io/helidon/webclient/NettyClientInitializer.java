/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
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
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpContentDecompressor;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.timeout.ReadTimeoutHandler;

class NettyClientInitializer extends ChannelInitializer<SocketChannel> {
    private final RequestConfiguration configuration;
    private final CompletableFuture<ClientResponse> future;

    NettyClientInitializer(RequestConfiguration configuration, CompletableFuture<ClientResponse> future) {
        this.configuration = configuration;
        this.future = future;
    }

    @Override
    protected void initChannel(SocketChannel channel) {
        ChannelPipeline pipeline = channel.pipeline();

        InetSocketAddress address = channel.remoteAddress();

        // read timeout (we also want to timeout waiting on a proxy)
        Duration readTimeout = configuration.readTimout();
        pipeline.addLast("readTimeout", new ReadTimeoutHandler(readTimeout.toMillis(), TimeUnit.MILLISECONDS));

        // proxy configuration
        configuration.proxy()
                .flatMap(proxy -> proxy.handler(address))
                .ifPresent(pipeline::addLast);

        // SSL configuration
        configuration.sslContext().ifPresent(ctx -> {
            pipeline.addLast(ctx.newHandler(channel.alloc()));
        });

        pipeline.addLast("logger", new LoggingHandler(LogLevel.TRACE));
        pipeline.addLast("httpCodec", new HttpClientCodec());
        pipeline.addLast("httpDecompressor", new HttpContentDecompressor());
        pipeline.addLast("helidonHandler", new NettyClientHandler(future));
    }
}
