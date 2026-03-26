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

package io.helidon.declarative.codegen.grpc.server;

import io.helidon.common.types.TypeName;

final class RpcServerTypes {
    static final TypeName ANNOTATION_ENDPOINT = TypeName.create("io.helidon.webserver.grpc.RpcServer.Endpoint");
    static final TypeName ANNOTATION_LISTENER = TypeName.create("io.helidon.webserver.grpc.RpcServer.Listener");
    static final TypeName ANNOTATION_SERVICE_NAME = TypeName.create("io.helidon.webserver.grpc.RpcServer.ServiceName");
    static final TypeName ANNOTATION_INTERCEPTORS =
            TypeName.create("io.helidon.webserver.grpc.RpcServer.Interceptors");
    static final TypeName ANNOTATION_MARSHALLER =
            TypeName.create("io.helidon.webserver.grpc.RpcServer.Marshaller");
    static final TypeName ANNOTATION_PROTO = TypeName.create("io.helidon.webserver.grpc.RpcServer.Proto");
    static final TypeName ANNOTATION_UNARY = TypeName.create("io.helidon.webserver.grpc.RpcServer.Unary");
    static final TypeName ANNOTATION_SERVER_STREAMING =
            TypeName.create("io.helidon.webserver.grpc.RpcServer.ServerStreaming");
    static final TypeName ANNOTATION_CLIENT_STREAMING =
            TypeName.create("io.helidon.webserver.grpc.RpcServer.ClientStreaming");
    static final TypeName ANNOTATION_BIDIRECTIONAL =
            TypeName.create("io.helidon.webserver.grpc.RpcServer.Bidirectional");

    static final TypeName SERVER_INTERCEPTOR = TypeName.create("io.grpc.ServerInterceptor");
    static final TypeName MARSHALLER_SUPPLIER = TypeName.create("io.helidon.grpc.core.MarshallerSupplier");
    static final TypeName RESPONSE_HELPER = TypeName.create("io.helidon.grpc.core.ResponseHelper");
    static final TypeName GRPC_ROUTE_REGISTRATION = TypeName.create("io.helidon.webserver.grpc.GrpcRouteRegistration");
    static final TypeName GRPC_SERVICE_DESCRIPTOR = TypeName.create("io.helidon.webserver.grpc.GrpcServiceDescriptor");
    static final TypeName GRPC_ENTRY_POINTS = TypeName.create("io.helidon.webserver.grpc.GrpcEntryPoint.EntryPoints");
    static final TypeName WEB_SERVER = TypeName.create("io.helidon.webserver.WebServer");
    static final TypeName COMPLETION_STAGE = TypeName.create("java.util.concurrent.CompletionStage");
    static final TypeName COMPLETABLE_FUTURE = TypeName.create("java.util.concurrent.CompletableFuture");
    static final TypeName STREAM = TypeName.create("java.util.stream.Stream");
    static final TypeName GRPC_UNARY_METHOD = TypeName.create("io.grpc.stub.ServerCalls.UnaryMethod");
    static final TypeName GRPC_SERVER_STREAMING_METHOD =
            TypeName.create("io.grpc.stub.ServerCalls.ServerStreamingMethod");
    static final TypeName GRPC_CLIENT_STREAMING_METHOD =
            TypeName.create("io.grpc.stub.ServerCalls.ClientStreamingMethod");
    static final TypeName GRPC_BIDI_STREAMING_METHOD =
            TypeName.create("io.grpc.stub.ServerCalls.BidiStreamingMethod");
    static final TypeName STREAM_OBSERVER = TypeName.create("io.grpc.stub.StreamObserver");
    static final TypeName PROTO_FILE_DESCRIPTOR = TypeName.create("com.google.protobuf.Descriptors.FileDescriptor");

    private RpcServerTypes() {
    }
}
