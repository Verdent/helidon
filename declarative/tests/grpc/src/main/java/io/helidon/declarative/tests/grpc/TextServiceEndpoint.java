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

import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import io.helidon.webserver.grpc.RpcServer;
import io.helidon.metrics.api.Metrics;
import io.helidon.tracing.Span;
import io.helidon.tracing.Tracing;

import com.google.protobuf.Descriptors;
import io.grpc.stub.StreamObserver;

@RpcServer.Interceptors(TextServiceServerInterceptor.class)
@RpcServer.Endpoint
@RpcServer.Listener("@default")
@RpcServer.ServiceName("TextService")
class TextServiceEndpoint {
    @RpcServer.Proto
    Descriptors.FileDescriptor proto() {
        return TextMessages.getDescriptor();
    }

    @RpcServer.Unary("Upper")
    @RpcServer.Interceptors(TextServiceServerUpperInterceptor.class)
    @Metrics.Counted(value = "grpc-upper-count", absoluteName = true)
    @Tracing.Traced(value = "grpc.upper", tags = @Tracing.Tag(key = "transport", value = "grpc"),
                    kind = Span.Kind.SERVER)
    TextMessages.TextMessage upper(TextMessages.TextMessage request) {
        return TextMessages.TextMessage.newBuilder()
                .setText(request.getText().toUpperCase(Locale.ROOT))
                .build();
    }

    @RpcServer.ServerStreaming("Split")
    Iterable<TextMessages.TextMessage> split(TextMessages.TextMessage request) {
        if (request.getText().isBlank()) {
            return List.of();
        }

        return Stream.of(request.getText().split(" "))
                .filter(part -> !part.isEmpty())
                .map(TextServiceEndpoint::message)
                .toList();
    }

    @RpcServer.ClientStreaming("Join")
    @Metrics.Counted(value = "grpc-join-count", absoluteName = true)
    @Tracing.Traced(value = "grpc.join", tags = @Tracing.Tag(key = "transport", value = "grpc"),
                    kind = Span.Kind.SERVER)
    TextMessages.TextMessage join(Iterable<TextMessages.TextMessage> requests) {
        StringBuilder text = new StringBuilder();
        for (TextMessages.TextMessage request : requests) {
            if (text.length() > 0) {
                text.append(' ');
            }
            text.append(request.getText());
        }
        return message(text.toString());
    }

    @RpcServer.Bidirectional("Echo")
    StreamObserver<TextMessages.TextMessage> echo(StreamObserver<TextMessages.TextMessage> observer) {
        return new StreamObserver<>() {
            @Override
            public void onNext(TextMessages.TextMessage value) {
                observer.onNext(value);
            }

            @Override
            public void onError(Throwable t) {
                observer.onError(t);
            }

            @Override
            public void onCompleted() {
                observer.onCompleted();
            }
        };
    }

    private static TextMessages.TextMessage message(String text) {
        return TextMessages.TextMessage.newBuilder()
                .setText(text)
                .build();
    }
}
