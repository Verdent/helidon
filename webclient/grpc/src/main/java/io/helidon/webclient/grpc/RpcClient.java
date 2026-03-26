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

package io.helidon.webclient.grpc;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import io.helidon.service.registry.Service;

/**
 * APIs to define a declarative gRPC client.
 * <p>
 * Declarative code generation creates a singleton implementation qualified with {@link Client}.
 * RPC methods may be declared directly on the annotated interface or inherited from parent interfaces.
 */
public final class RpcClient {
    private RpcClient() {
    }

    /**
     * Definition of a typed gRPC client.
     * <p>
     * The annotated type must be an interface.
     * Non-default methods declared on the interface or inherited from its parent interfaces
     * are considered gRPC methods.
     * <p>
     * The base of configuration for a declarative client is the fully qualified name of the
     * annotated interface. This key can be overridden using {@link #configKey()}.
     */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    public @interface Endpoint {
        /**
         * Target URI of the remote gRPC endpoint.
         * <p>
         * The value can use declarative configuration expressions such as
         * {@code ${text-service.client.uri:http://localhost:8080}}.
         * <p>
         * If left blank, the URI may be provided through configuration under {@link #configKey()}.
         * The URI is only required when the generated client must create a dedicated
         * {@code GrpcClient} instance.
         * <p>
         * If a dedicated client is created from this URI and the URI starts with {@code http://},
         * TLS is disabled for that generated client instance.
         *
         * @return endpoint URI
         */
        String value();

        /**
         * Configuration key base to use when looking up options for the generated client.
         * <p>
         * Supported keys are:
         * <ul>
         *     <li>{@code uri} - remote gRPC endpoint URI</li>
         *     <li>{@code client} - gRPC client configuration subtree</li>
         * </ul>
         *
         * @return configuration key prefix
         */
        String configKey() default "";

        /**
         * Name of a named {@code GrpcClient} instance from the service registry to use.
         * <p>
         * This value is a static service registry name.
         *
         * @return registry client name
         */
        String clientName() default "";
    }

    /**
     * Qualifier for injection points of generated typed gRPC clients.
     */
    @Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.TYPE})
    @Documented
    @Service.Qualifier
    public @interface Client {
    }

    /**
     * Remote gRPC service name.
     * <p>
     * For protobuf services with a package, this should be the canonical fully qualified
     * gRPC service name, such as {@code example.hello.Greeter} or the generated
     * {@code *Grpc.SERVICE_NAME} constant.
     * <p>
     * The value can use declarative configuration expressions such as
     * {@code ${text-service.grpc.service-name:grpc.declarative.TextService}}.
     * <p>
     * If not defined, the annotated interface simple name is used, which only matches
     * services whose gRPC service name is also unqualified.
     */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Inherited
    public @interface ServiceName {
        /**
         * gRPC service name.
         *
         * @return service name
         */
        String value();
    }

    /**
     * Declares an ordered list of gRPC client interceptors.
     * <p>
     * May be used on the client interface to define interceptors for all RPC methods, or on an individual
     * RPC method to add method-specific interceptors.
     */
    @Target({ElementType.TYPE, ElementType.METHOD})
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Inherited
    public @interface Interceptors {
        /**
         * Ordered interceptor classes.
         *
         * @return interceptor classes
         */
        Class<?>[] value();
    }

    /**
     * Declares the named marshaller supplier for a typed gRPC client or one of its RPC methods.
     * <p>
     * May be used on the client interface to define the default marshaller supplier for all RPC methods,
     * or on an individual RPC method to override the default.
     */
    @Target({ElementType.TYPE, ElementType.METHOD})
    @Retention(RetentionPolicy.CLASS)
    @Documented
    @Inherited
    public @interface Marshaller {
        /**
         * The built-in protobuf marshaller supplier name.
         */
        String PROTO = "proto";

        /**
         * The built-in default marshaller supplier name.
         */
        String DEFAULT = "default";

        /**
         * Named marshaller supplier to use.
         *
         * @return marshaller supplier name
         */
        String value() default DEFAULT;
    }

    /**
     * Marks a unary gRPC client method.
     * <p>
     * Supported method shapes: {@code ResponseT method(RequestT request)} and {@code ResponseT method()}.
     * Default interface methods are ignored by declarative code generation.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
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
     * Marks a server-streaming gRPC client method.
     * <p>
     * Supported method shapes:
     * {@code java.util.Iterator<ResponseT> method(RequestT request)} and
     * {@code java.util.Iterator<ResponseT> method()}.
     * Default interface methods are ignored by declarative code generation.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
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
     * Marks a client-streaming gRPC client method.
     * <p>
     * Supported method shapes:
     * {@code ResponseT method(java.lang.Iterable<RequestT> request)} and
     * {@code ResponseT method(java.util.Iterator<RequestT> request)}.
     * Default interface methods are ignored by declarative code generation.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
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
     * Marks a bidirectional-streaming gRPC client method.
     * <p>
     * Supported method shape: {@code java.util.Iterator<ResponseT> method(java.util.Iterator<RequestT> request)}.
     * Default interface methods are ignored by declarative code generation.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
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
