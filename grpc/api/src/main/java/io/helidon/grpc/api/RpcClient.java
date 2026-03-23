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
 * APIs to define a declarative gRPC client.
 */
public final class RpcClient {
    private RpcClient() {
    }

    /**
     * Definition of a typed gRPC client.
     */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    public @interface Endpoint {
        /**
         * Target URI of the remote gRPC endpoint.
         * <p>
         * The value can use declarative configuration expressions such as
         * {@code ${string-service.client.uri:http://localhost:8080}}.
         *
         * @return endpoint URI
         */
        String value();

        /**
         * Name of a named {@code GrpcClient} instance from the service registry to use.
         * <p>
         * If the named client is not available, a new client is created from the configured URI.
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
     * Marks a unary gRPC client method.
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
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    public @interface ServerStreaming {
        /**
         * Name of the gRPC method.
         *
         * @return gRPC method name
         */
        String value() default "";
    }

    /**
     * Marks a client-streaming gRPC client method.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    public @interface ClientStreaming {
        /**
         * Name of the gRPC method.
         *
         * @return gRPC method name
         */
        String value() default "";
    }

    /**
     * Marks a bidirectional-streaming gRPC client method.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.CLASS)
    @Documented
    public @interface Bidirectional {
        /**
         * Name of the gRPC method.
         *
         * @return gRPC method name
         */
        String value() default "";
    }
}
