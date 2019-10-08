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

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.helidon.common.GenericType;
import io.helidon.common.context.Context;
import io.helidon.common.http.Headers;
import io.helidon.common.http.Http;
import io.helidon.common.http.HttpRequest;
import io.helidon.common.http.MediaType;
import io.helidon.common.http.Parameters;
import io.helidon.common.reactive.Flow;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;

class ClientRequestBuilderImpl implements ClientRequestBuilder {
    private final Map<String, Object> properties = new HashMap<>();
    private final LazyValue<NioEventLoopGroup> eventGroup;
    private final ClientConfiguration configuration;
    private final RequestConfiguration.Builder requestConfigurationBuilder;
    private final Http.Method method;

    private URI uri;
    private Context context;

    ClientRequestBuilderImpl(LazyValue<NioEventLoopGroup> eventGroup,
                                    ClientConfiguration configuration,
                                    Http.Method method) {

        this.eventGroup = eventGroup;
        this.configuration = configuration;
        this.method = method;
        this.requestConfigurationBuilder = RequestConfiguration.builder()
                .update(configuration);
    }

    public static ClientRequestBuilder create(LazyValue<NioEventLoopGroup> eventGroup,
                                              ClientConfiguration configuration,
                                              Http.Method method) {
        return new ClientRequestBuilderImpl(eventGroup, configuration, method);
    }

    @Override
    public ClientRequestBuilder uri(String uri) {
        this.uri = URI.create(uri);
        return this;
    }

    @Override
    public ClientRequestBuilder uri(URL url) {
        try {
            this.uri = url.toURI();
        } catch (URISyntaxException e) {
            throw new ClientException("Failed to create URI from URL", e);
        }
        return this;
    }

    @Override
    public ClientRequestBuilder uri(URI uri) {
        this.uri = uri;
        return this;
    }

    @Override
    public ClientRequestBuilder property(String propertyName, Object propertyValue) {
        properties.put(propertyName, propertyValue);
        return this;
    }

    @Override
    public ClientRequestBuilder context(Context context) {
        this.context = context;
        return this;
    }

    @Override
    public ClientRequestBuilder header(String header, String... values) {
        return null;
    }

    @Override
    public ClientRequestHeaders headers() {
        return null;
    }

    @Override
    public ClientRequestBuilder queryParam(String name, String... values) {
        return null;
    }

    @Override
    public ClientRequestBuilder proxy(Proxy proxy) {
        return null;
    }

    @Override
    public ClientRequestBuilder headers(Headers headers) {
        return null;
    }

    @Override
    public ClientRequestBuilder queryParams(Parameters queryParams) {
        return null;
    }

    @Override
    public ClientRequestBuilder register(ClientContentHandler<?> handler) {
        return null;
    }

    @Override
    public ClientRequestBuilder path(HttpRequest.Path path) {
        return null;
    }

    @Override
    public ClientRequestBuilder contentType(MediaType mediaType) {
        return null;
    }

    @Override
    public ClientRequestBuilder contentLength(long length) {
        return null;
    }

    @Override
    public ClientRequestBuilder ifModifiedSince(ZonedDateTime time) {
        return null;
    }

    @Override
    public ClientRequestBuilder ifNoneMatch(String... etags) {
        return null;
    }

    @Override
    public ClientRequestBuilder accept(MediaType... mediaTypes) {
        return null;
    }

    @Override
    public <T> CompletionStage<T> request(Class<T> responseType) {
        CompletableFuture<ClientResponse> result = new CompletableFuture<ClientResponse>();

        EventLoopGroup group = eventGroup.get();
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(group)
                .channel(NioSocketChannel.class)
                .handler(new NettyClientInitializer(requestConfigurationBuilder.build(), result))
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) configuration.connectTimeout().toMillis());

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                                                                    toNettyMethod(method),
                                                                    uri.getPath(),
                                                                    Unpooled.EMPTY_BUFFER);
        HttpHeaders headers = request.headers();
        headers.set(HttpHeaderNames.HOST, uri.getHost());
        headers.set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
        headers.set(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.GZIP);

        bootstrap.connect(uri.getHost(), uri.getPort())
                .addListener(new ChannelFutureListener() {
                    @Override
                    public void operationComplete(ChannelFuture future) {
                        Throwable cause = future.cause();
                        if (null == cause) {
                            future.channel().writeAndFlush(request);
                        } else {
                            result.completeExceptionally(cause);
                        }
                    }
                });

        return result.thenApply(ClientResponse::content)
                .thenCompose(content -> content.as(responseType));
    }

    private HttpMethod toNettyMethod(Http.Method method) {
        return HttpMethod.valueOf(method.name());
    }

    @Override
    public <T> CompletionStage<T> request(GenericType<T> responseType) {
        return null;
    }

    @Override
    public CompletionStage<ClientResponse> submit() {
        return null;
    }

    @Override
    public <T> CompletionStage<T> submit(Flow.Publisher<?> requestEntity, Class<T> responseType) {
        return null;
    }

    @Override
    public <T> CompletionStage<T> submit(Object requestEntity, Class<T> resposneType) {
        return null;
    }

    @Override
    public CompletionStage<ClientResponse> submit(Flow.Publisher<?> requestEntity) {
        return null;
    }

    @Override
    public CompletionStage<ClientResponse> submit(Object requestEntity) {
        return null;
    }
}
