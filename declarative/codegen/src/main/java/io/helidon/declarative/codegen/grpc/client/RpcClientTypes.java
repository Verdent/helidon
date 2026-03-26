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

package io.helidon.declarative.codegen.grpc.client;

import io.helidon.common.types.Annotation;
import io.helidon.common.types.TypeName;

final class RpcClientTypes {
    static final TypeName ANNOTATION_ENDPOINT = TypeName.create("io.helidon.webclient.grpc.RpcClient.Endpoint");
    static final TypeName ANNOTATION_CLIENT_QUALIFIER = TypeName.create("io.helidon.webclient.grpc.RpcClient.Client");
    static final TypeName ANNOTATION_SERVICE_NAME = TypeName.create("io.helidon.webclient.grpc.RpcClient.ServiceName");
    static final TypeName ANNOTATION_INTERCEPTORS =
            TypeName.create("io.helidon.webclient.grpc.RpcClient.Interceptors");
    static final TypeName ANNOTATION_MARSHALLER =
            TypeName.create("io.helidon.webclient.grpc.RpcClient.Marshaller");
    static final TypeName ANNOTATION_UNARY = TypeName.create("io.helidon.webclient.grpc.RpcClient.Unary");
    static final TypeName ANNOTATION_SERVER_STREAMING =
            TypeName.create("io.helidon.webclient.grpc.RpcClient.ServerStreaming");
    static final TypeName ANNOTATION_CLIENT_STREAMING =
            TypeName.create("io.helidon.webclient.grpc.RpcClient.ClientStreaming");
    static final TypeName ANNOTATION_BIDIRECTIONAL =
            TypeName.create("io.helidon.webclient.grpc.RpcClient.Bidirectional");

    static final TypeName CLIENT_INTERCEPTOR = TypeName.create("io.grpc.ClientInterceptor");
    static final TypeName MARSHALLER_SUPPLIER = TypeName.create("io.helidon.grpc.core.MarshallerSupplier");
    static final TypeName GRPC_CLIENT = TypeName.create("io.helidon.webclient.grpc.GrpcClient");
    static final TypeName GRPC_CLIENT_CONFIG = TypeName.create("io.helidon.webclient.grpc.GrpcClientConfig");
    static final TypeName GRPC_SERVICE_CLIENT = TypeName.create("io.helidon.webclient.grpc.GrpcServiceClient");
    static final TypeName GRPC_SERVICE_DESCRIPTOR = TypeName.create("io.helidon.webclient.grpc.GrpcServiceDescriptor");
    static final TypeName GRPC_CLIENT_METHOD_DESCRIPTOR =
            TypeName.create("io.helidon.webclient.grpc.GrpcClientMethodDescriptor");
    static final TypeName PROTO_EMPTY = TypeName.create("com.google.protobuf.Empty");
    static final TypeName ITERABLE = TypeName.create("java.lang.Iterable");
    static final TypeName ITERATOR = TypeName.create("java.util.Iterator");
    static final TypeName STREAM = TypeName.create("java.util.stream.Stream");
    static final TypeName STREAM_OBSERVER = TypeName.create("io.grpc.stub.StreamObserver");

    static final Annotation RPC_CLIENT_QUALIFIER_INSTANCE = Annotation.create(ANNOTATION_CLIENT_QUALIFIER);

    private RpcClientTypes() {
    }
}
