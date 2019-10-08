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

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import io.helidon.common.http.DataChunk;
import io.helidon.common.http.Http;
import io.helidon.common.reactive.Flow;
import io.helidon.common.reactive.SubmissionPublisher;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.LastHttpContent;

/**
 * Created for each request/response interaction.
 */
class NettyClientHandler extends SimpleChannelInboundHandler<HttpObject> {

    private final ClientResponseImpl.Builder clientResponse;
    private final ResponseContentPublisher publisher;
    private final CompletableFuture<ClientResponse> responseFuture;

    NettyClientHandler(CompletableFuture<ClientResponse> responseFuture) {
        this.responseFuture = responseFuture;

        //        CookieHandler cookieHandler = CookieManager.getDefault();
        this.clientResponse = ClientResponseImpl.builder();
        this.publisher = new ResponseContentPublisher();
        this.clientResponse.contentPublisher(publisher);
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        ctx.flush();
        // if we can read next
//        if (wantMore()) {
//            ctx.channel().read();
//        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) {
        if (msg instanceof HttpResponse) {
            // TODO enable backpressure
            //ctx.channel().config().setAutoRead(false);

            HttpResponse response = (HttpResponse) msg;
            clientResponse.status(helidonStatus(response.status()));
            clientResponse.httpVersion(Http.Version.create(response.protocolVersion().toString()));

            HttpHeaders nettyHeaders = response.headers();

            for (String name : nettyHeaders.names()) {
                List<String> values = nettyHeaders.getAll(name);
                clientResponse.addHeader(name, values);
            }

            // we got a response, we can safely complete the future
            // all errors are now fed only to the publisher
            responseFuture.complete(clientResponse.build());
        }

        // never "else-if" - msg may be an instance of more than one type, we must process all of them
        if (msg instanceof HttpContent) {
            HttpContent content = (HttpContent) msg;
            publisher.submit(toDataChunk(content));
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
            publisher.completeExceptionally(cause);
        } else {
            // we failed before getting response
            responseFuture.completeExceptionally(cause);
        }
        ctx.close();
    }

    private DataChunk toDataChunk(HttpContent content) {
        final ByteBuf buf = content.content();
        return DataChunk.create(false,
                                buf.nioBuffer().asReadOnlyBuffer(),
                                buf::release,
                                true);
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

    private static final class ResponseContentPublisher implements Flow.Publisher<DataChunk> {
        private final SubmissionPublisher<DataChunk> publisher;

        ResponseContentPublisher() {
            this.publisher = new SubmissionPublisher<>();
        }

        @Override
        public void subscribe(Flow.Subscriber<? super DataChunk> subscriber) {
            this.publisher.subscribe(subscriber);
        }

        public void submit(DataChunk dataChunk) {
            this.publisher.submit(dataChunk);
        }

        public void complete() {
            this.publisher.close();
        }

        public void completeExceptionally(Throwable cause) {
            this.publisher.closeExceptionally(cause);
        }
    }
}
