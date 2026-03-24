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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import io.helidon.declarative.codegen.grpc.GrpcCodegenTestSupport;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class GrpcServerCodegenTest {
    @Test
    void testUnaryEndpointCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import com.google.protobuf.Descriptors;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.grpc.api.RpcServer;

                        @RpcServer.Endpoint
                        @RpcServer.ServiceName("example.Greeter")
                        class GreeterEndpoint {
                            @RpcServer.Proto
                            Descriptors.FileDescriptor proto() {
                                return null;
                            }

                            @RpcServer.Unary("SayHello")
                            void sayHello(String request, StreamObserver<String> observer) {
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterEndpoint__GrpcRouteRegistration.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("class GreeterEndpoint__GrpcRouteRegistration implements GrpcRouteRegistration"));
        assertThat(content, containsString("entryPoints.unary("));
        assertThat(content, containsString("\"SayHello\""));
    }

    @Test
    void testInterfaceMethodAnnotationCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterContract.java", """
                        package com.example;

                        import io.grpc.stub.StreamObserver;
                        import io.helidon.grpc.api.RpcServer;

                        interface GreeterContract {
                            @RpcServer.Unary("SayHello")
                            void sayHello(String request, StreamObserver<String> observer);
                        }
                        """)
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import com.google.protobuf.Descriptors;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.grpc.api.RpcServer;

                        @RpcServer.Endpoint
                        class GreeterEndpoint implements GreeterContract {
                            @RpcServer.Proto
                            static Descriptors.FileDescriptor proto() {
                                return null;
                            }

                            @Override
                            public void sayHello(String request, StreamObserver<String> observer) {
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterEndpoint__GrpcRouteRegistration.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("\"SayHello\""));
        assertThat(content, containsString("entryPoints.unary("));
    }

    @Test
    void testUnaryMethodNameDefaultsToJavaName() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import com.google.protobuf.Descriptors;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.grpc.api.RpcServer;

                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Proto
                            Descriptors.FileDescriptor proto() {
                                return null;
                            }

                            @RpcServer.Unary
                            void sayHello(String request, StreamObserver<String> observer) {
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterEndpoint__GrpcRouteRegistration.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("serviceName = \"GreeterEndpoint\";"));
        assertThat(content, containsString("\"sayHello\""));
    }

    @Test
    void testInterfaceEndpointRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("BrokenEndpoint.java", """
                        package com.example;

                        import io.helidon.grpc.api.RpcServer;

                        @RpcServer.Endpoint
                        interface BrokenEndpoint {
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Interfaces should not be annotated with "
                                          + "io.helidon.grpc.api.RpcServer.Endpoint"));
    }

    @Test
    void testUnaryMethodSignatureRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("BrokenUnaryEndpoint.java", """
                        package com.example;

                        import com.google.protobuf.Descriptors;
                        import io.helidon.grpc.api.RpcServer;

                        @RpcServer.Endpoint
                        class BrokenUnaryEndpoint {
                            @RpcServer.Proto
                            Descriptors.FileDescriptor proto() {
                                return null;
                            }

                            @RpcServer.Unary
                            void sayHello(String request) {
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Unary declarative gRPC method must declare exactly two parameters"));
    }
}
