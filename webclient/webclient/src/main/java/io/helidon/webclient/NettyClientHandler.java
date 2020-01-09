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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import io.helidon.common.http.DataChunk;
import io.helidon.common.http.Http;
import io.helidon.common.reactive.OriginThreadPublisher;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.LastHttpContent;

import static io.helidon.webclient.ClientRequestBuilderImpl.REQUEST;

/**
 * Created for each request/response interaction.
 */
class NettyClientHandler extends SimpleChannelInboundHandler<HttpObject> {

    private static final List<HttpInterceptor> HTTP_INTERCEPTORS = new ArrayList<>();

    static {
        HTTP_INTERCEPTORS.add(new RedirectInterceptor());
    }

    private final ClientResponseImpl.Builder clientResponse;
    private final CompletableFuture<ClientResponse> responseFuture;
    private HttpResponsePublisher publisher;

    /**
     * Creates new instance.
     *
     * @param responseFuture response future
     */
    NettyClientHandler(CompletableFuture<ClientResponse> responseFuture) {
        this.responseFuture = responseFuture;
        this.clientResponse = ClientResponseImpl.builder();
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        ctx.flush();
        if (publisher != null && publisher.tryAcquire() > 0) {
            ctx.channel().read();
        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) throws IOException {
        if (msg instanceof HttpResponse) {

            ctx.channel().config().setAutoRead(false);

            this.publisher = new HttpResponsePublisher(ctx);
            this.clientResponse.contentPublisher(publisher);

            //publisher = new HttpResponsePublisher(ctx);
            ClientRequestBuilder.ClientRequest clientRequest = ctx.channel().attr(REQUEST).get();
            HttpResponse response = (HttpResponse) msg;
            for (HttpInterceptor interceptor : HTTP_INTERCEPTORS) {
                if (interceptor.shouldIntercept(response.status(), clientRequest.configuration())) {
                    interceptor.handleInterception(response, clientRequest, responseFuture);
                    if (!interceptor.continueAfterInterception()) {
                        publisher.complete();
                        ctx.close();
                        return;
                    }
                }
            }
            clientResponse.status(helidonStatus(response.status()));
            clientResponse.httpVersion(Http.Version.create(response.protocolVersion().toString()));

            HttpHeaders nettyHeaders = response.headers();
            for (String name : nettyHeaders.names()) {
                List<String> values = nettyHeaders.getAll(name);
                clientResponse.addHeader(name, values);
            }

            // we got a response, we can safely complete the future
            // all errors are now fed only to the publisher
            ClientResponse clientResponse = this.clientResponse.build();
            clientRequest.configuration().cookieManager().put(clientRequest.configuration().requestURI(),
                                                              clientResponse.headers().toMap());
            responseFuture.complete(clientResponse);
        }

        // never "else-if" - msg may be an instance of more than one type, we must process all of them
        if (msg instanceof HttpContent) {
            HttpContent content = (HttpContent) msg;
            publisher.submit(content.content());
        }

        if (msg instanceof LastHttpContent) {
            publisher.complete();
            ctx.close();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        if (responseFuture.isDone()) {
            // we failed during entity processing
            publisher.error(cause);
        } else {
            // we failed before getting response
            responseFuture.completeExceptionally(cause);
        }
        ctx.close();
    }

    private Http.ResponseStatus helidonStatus(HttpResponseStatus nettyStatus) {
        final int statusCode = nettyStatus.code();

        Optional<Http.Status> status = Http.Status.find(statusCode);
        if (status.isPresent()) {
            return status.get();
        }
        return new Http.ResponseStatus() {
            @Override
            public int code() {
                return statusCode;
            }

            @Override
            public Family family() {
                return Family.of(statusCode);
            }

            @Override
            public String reasonPhrase() {
                return nettyStatus.reasonPhrase();
            }
        };
    }

    private static final class HttpResponsePublisher extends OriginThreadPublisher<DataChunk, ByteBuf> {

        private final ReentrantReadWriteLock.WriteLock lock = new ReentrantReadWriteLock().writeLock();
        private final ChannelHandlerContext ctx;

        HttpResponsePublisher(ChannelHandlerContext ctx) {
            this.ctx = ctx;
        }

        @Override
        protected void hookOnRequested(long n, long result) {
            if (result == Long.MAX_VALUE) {
                ctx.channel().config().setAutoRead(true);
            } else {
                ctx.channel().config().setAutoRead(false);
            }

            try {
                lock.lock();
                if (super.tryAcquire() > 0) {
                    ctx.channel().read();
                }
            } finally {
                lock.unlock();
            }
        }

        @Override
        public long tryAcquire() {
            try {
                lock.lock();
                return super.tryAcquire();
            } finally {
                lock.unlock();
            }
        }

        @Override
        protected DataChunk wrap(ByteBuf buf) {
            buf.retain();
            return DataChunk.create(false,
                                    buf.nioBuffer().asReadOnlyBuffer(),
                                    buf::release,
                                    true);
        }

    }

}
