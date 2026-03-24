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

package io.helidon.grpc.api;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import io.helidon.service.registry.Service;

/**
 * APIs to define declarative gRPC server endpoints.
 * <p>
 * Method annotations may be declared directly on endpoint methods or on matching methods inherited
 * from implemented interfaces. Generated handlers are wrapped through
 * {@code io.helidon.webserver.grpc.GrpcEntryPoint.EntryPoints}, so declarative entry-point
 * interceptors can participate in gRPC invocations.
 */
public final class RpcServer {
    private RpcServer() {
    }

    /**
     * Definition of a gRPC server endpoint.
     * <p>
     * The annotated type must be a concrete class.
     */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Inherited
    @Service.Singleton
    public @interface Endpoint {
    }

    /**
     * Service name exposed through gRPC routing.
     * <p>
     * If not defined, the endpoint class simple name is used.
     * If the protobuf descriptor defines a package, both the simple service name and the
     * fully qualified protobuf service name are accepted.
     * The value can use declarative configuration expressions such as
     * {@code ${text-service.grpc.service-name:grpc.declarative.TextService}}.
     */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Inherited
    public @interface ServiceName {
        /**
         * Service name.
         *
         * @return service name
         */
        String value();
    }

    /**
     * Listener socket assigned to this endpoint.
     * <p>
     * The value can use declarative configuration expressions such as
     * {@code ${text-service.server.listener:@default}}.
     */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Inherited
    public @interface Listener {
        /**
         * Name of a listener on {@code WebServer}.
         *
         * @return listener name
         */
        String value();
    }

    /**
     * Marks a method that returns the protobuf descriptor for this service.
     * <p>
     * Declarative code generation expects exactly one such method on the endpoint type.
     * The method must declare no parameters and return
     * {@code com.google.protobuf.Descriptors.FileDescriptor}. It may be either instance or static.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    public @interface Proto {
    }

    /**
     * Marks a unary gRPC method.
     * <p>
     * Supported method shape:
     * {@code void method(RequestT request, io.grpc.stub.StreamObserver<ResponseT> observer)}.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Service.EntryPoint
    public @interface Unary {
        /**
         * Name of the gRPC method.
         * <p>
         * If not set, the Java method name is used.
         *
         * @return gRPC method name
         */
        String value() default "";
    }

    /**
     * Marks a server-streaming gRPC method.
     * <p>
     * Supported method shape:
     * {@code void method(RequestT request, io.grpc.stub.StreamObserver<ResponseT> observer)}.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Service.EntryPoint
    public @interface ServerStreaming {
        /**
         * Name of the gRPC method.
         * <p>
         * If not set, the Java method name is used.
         *
         * @return gRPC method name
         */
        String value() default "";
    }

    /**
     * Marks a client-streaming gRPC method.
     * <p>
     * Supported method shape:
     * {@code io.grpc.stub.StreamObserver<RequestT> method(io.grpc.stub.StreamObserver<ResponseT> observer)}.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Service.EntryPoint
    public @interface ClientStreaming {
        /**
         * Name of the gRPC method.
         * <p>
         * If not set, the Java method name is used.
         *
         * @return gRPC method name
         */
        String value() default "";
    }

    /**
     * Marks a bidirectional gRPC method.
     * <p>
     * Supported method shape:
     * {@code io.grpc.stub.StreamObserver<RequestT> method(io.grpc.stub.StreamObserver<ResponseT> observer)}.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Service.EntryPoint
    public @interface Bidirectional {
        /**
         * Name of the gRPC method.
         * <p>
         * If not set, the Java method name is used.
         *
         * @return gRPC method name
         */
        String value() default "";
    }
}
