/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
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

package io.helidon.declarative.tests.grpc;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import io.helidon.webserver.grpc.RpcServer;
import io.grpc.stub.StreamObserver;

@RpcServer.Endpoint
@RpcServer.Listener("@default")
@RpcServer.ServiceName(UnaryShapesEndpoint.SERVICE_NAME)
class UnaryShapesEndpoint {
    static final String SERVICE_NAME = "grpc.declarative.UnaryShapes";
    private static final AtomicReference<String> LAST_NOTIFY = new AtomicReference<>();
    private static final AtomicInteger PING_COUNT = new AtomicInteger();

    @RpcServer.Unary("DirectUpper")
    TextMessages.TextMessage directUpper(TextMessages.TextMessage request) {
        return upper("DIRECT", request);
    }

    @RpcServer.Unary("NoArgUpper")
    TextMessages.TextMessage noArgUpper() {
        return message("NO_ARG:HELLO");
    }

    @RpcServer.Unary("ObserverUpper")
    void observerUpper(StreamObserver<TextMessages.TextMessage> observer) {
        observer.onNext(message("OBSERVER:HELLO"));
        observer.onCompleted();
    }

    @RpcServer.Unary("Notify")
    void notify(TextMessages.TextMessage request) {
        LAST_NOTIFY.set(request.getText().toUpperCase(Locale.ROOT));
    }

    @RpcServer.Unary("Ping")
    void ping() {
        PING_COUNT.incrementAndGet();
    }

    @RpcServer.ServerStreaming("NoArgSplit")
    Stream<TextMessages.TextMessage> noArgSplit() {
        return Stream.of(message("alpha"), message("beta"));
    }

    @RpcServer.ServerStreaming("ObserverSplit")
    void observerSplit(StreamObserver<TextMessages.TextMessage> observer) {
        observer.onNext(message("observer"));
        observer.onNext(message("stream"));
        observer.onCompleted();
    }

    static void reset() {
        LAST_NOTIFY.set(null);
        PING_COUNT.set(0);
    }

    static String lastNotify() {
        return LAST_NOTIFY.get();
    }

    static int pingCount() {
        return PING_COUNT.get();
    }

    private static TextMessages.TextMessage upper(String prefix, TextMessages.TextMessage request) {
        return message(prefix + ":" + request.getText().toUpperCase(Locale.ROOT));
    }

    private static TextMessages.TextMessage message(String text) {
        return TextMessages.TextMessage.newBuilder()
                .setText(text)
                .build();
    }
}
