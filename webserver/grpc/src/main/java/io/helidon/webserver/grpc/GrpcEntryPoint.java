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

package io.helidon.webserver.grpc;

import java.util.List;

import io.helidon.common.types.Annotation;
import io.helidon.common.types.TypedElementInfo;
import io.helidon.service.registry.ServiceDescriptor;

import io.grpc.stub.ServerCalls;

/**
 * Container class for types related to gRPC entry points.
 *
 * @deprecated this API is part of incubating features of Helidon. This API may change including backward incompatible changes
 *               and full removal. We welcome feedback for incubating features.
 */
@Deprecated
public final class GrpcEntryPoint {
    private GrpcEntryPoint() {
    }

    /**
     * A contract used from generated code to invoke gRPC entry point interceptors.
     */
    public interface EntryPoints {
        /**
         * Wrap a unary method so entry point interceptors can participate in its invocation.
         *
         * @param descriptor descriptor of the invoked endpoint implementation
         * @param typeAnnotations annotations declared on the endpoint type
         * @param methodInfo method information for the invoked method
         * @param actualHandler actual unary handler
         * @param <ReqT> request type
         * @param <ResT> response type
         * @return wrapped unary handler
         */
        <ReqT, ResT> ServerCalls.UnaryMethod<ReqT, ResT> unary(ServiceDescriptor<?> descriptor,
                                                               List<Annotation> typeAnnotations,
                                                               TypedElementInfo methodInfo,
                                                               ServerCalls.UnaryMethod<ReqT, ResT> actualHandler);

        /**
         * Wrap a server-streaming method so entry point interceptors can participate in its invocation.
         *
         * @param descriptor descriptor of the invoked endpoint implementation
         * @param typeAnnotations annotations declared on the endpoint type
         * @param methodInfo method information for the invoked method
         * @param actualHandler actual server-streaming handler
         * @param <ReqT> request type
         * @param <ResT> response type
         * @return wrapped server-streaming handler
         */
        <ReqT, ResT> ServerCalls.ServerStreamingMethod<ReqT, ResT> serverStreaming(ServiceDescriptor<?> descriptor,
                                                                                   List<Annotation> typeAnnotations,
                                                                                   TypedElementInfo methodInfo,
                                                                                   ServerCalls.ServerStreamingMethod<ReqT, ResT> actualHandler);

        /**
         * Wrap a client-streaming method so entry point interceptors can participate in its invocation.
         *
         * @param descriptor descriptor of the invoked endpoint implementation
         * @param typeAnnotations annotations declared on the endpoint type
         * @param methodInfo method information for the invoked method
         * @param actualHandler actual client-streaming handler
         * @param <ReqT> request type
         * @param <ResT> response type
         * @return wrapped client-streaming handler
         */
        <ReqT, ResT> ServerCalls.ClientStreamingMethod<ReqT, ResT> clientStreaming(ServiceDescriptor<?> descriptor,
                                                                                   List<Annotation> typeAnnotations,
                                                                                   TypedElementInfo methodInfo,
                                                                                   ServerCalls.ClientStreamingMethod<ReqT, ResT> actualHandler);

        /**
         * Wrap a bidirectional-streaming method so entry point interceptors can participate in its invocation.
         *
         * @param descriptor descriptor of the invoked endpoint implementation
         * @param typeAnnotations annotations declared on the endpoint type
         * @param methodInfo method information for the invoked method
         * @param actualHandler actual bidirectional-streaming handler
         * @param <ReqT> request type
         * @param <ResT> response type
         * @return wrapped bidirectional-streaming handler
         */
        <ReqT, ResT> ServerCalls.BidiStreamingMethod<ReqT, ResT> bidirectional(ServiceDescriptor<?> descriptor,
                                                                                List<Annotation> typeAnnotations,
                                                                                TypedElementInfo methodInfo,
                                                                                ServerCalls.BidiStreamingMethod<ReqT, ResT> actualHandler);
    }
}
