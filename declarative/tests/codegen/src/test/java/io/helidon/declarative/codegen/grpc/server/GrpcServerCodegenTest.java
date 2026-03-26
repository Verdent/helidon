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
import io.helidon.service.registry.Service;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

class GrpcServerCodegenTest {
    @Test
    void testUnaryEndpointCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import com.google.protobuf.Descriptors;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

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
        var generatedDescriptor = result.sourceOutput().resolve("com/example/GreeterEndpoint__ServiceDescriptor.java");
        assertThat(Files.exists(generated), is(true));
        assertThat(Files.exists(generatedDescriptor), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("class GreeterEndpoint__GrpcRouteRegistration implements GrpcRouteRegistration"));
        assertThat(content, containsString("entryPoints.unary("));
        assertThat(content, containsString("\"SayHello\""));
        assertThat(content, containsString("var proto = endpoint.proto();"));
        assertThat(content, containsString("endpoint::sayHello"));
        assertThat(content, containsString("descriptorBuilder.proto(proto);"));

        String descriptorContent = Files.readString(generatedDescriptor, StandardCharsets.UTF_8);
        assertThat(descriptorContent, containsString(Service.Singleton.class.getCanonicalName()));
    }

    @Test
    void testPerLookupUnaryEndpointCodegenWithoutProto() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import io.grpc.stub.StreamObserver;
                        import io.helidon.service.registry.Service;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        @Service.PerLookup
                        @RpcServer.ServiceName("example.Greeter")
                        class GreeterEndpoint {
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
        assertThat(content, containsString("var descriptorBuilder = GrpcServiceDescriptor.builder("));
        assertThat(content, containsString("entryPoints.unary("));
        assertThat(content, not(containsString("var proto = ")));
        assertThat(content, not(containsString("descriptorBuilder.proto(proto);")));
        assertThat(content, containsString("(String request, StreamObserver<String> observer) -> "
                                                  + "endpoint.get().sayHello(request, observer)"));
    }

    @Test
    void testSingletonEndpointCodegenUsesDirectEndpointReference() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import com.google.protobuf.Descriptors;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.service.registry.Service;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        @Service.Singleton
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
        assertThat(content, containsString("var proto = endpoint.proto();"));
        assertThat(content, containsString("endpoint::sayHello"));
    }

    @Test
    void testUnaryEndpointCodegenSupportsReturnedResponse() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Unary("SayHello")
                            String sayHello(String request) {
                                return request.toUpperCase();
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterEndpoint__GrpcRouteRegistration.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("ResponseHelper.complete(observer, endpoint.sayHello(request))"));
    }

    @Test
    void testUnaryEndpointCodegenRejectsCompletableFutureResponse() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import java.util.concurrent.CompletableFuture;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Unary("SayHello")
                            CompletableFuture<String> sayHello(String request) {
                                return CompletableFuture.completedFuture(request.toUpperCase());
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Unary declarative gRPC method must not use "
                                          + "java.util.concurrent.CompletableFuture "
                                          + "as a return type"));
    }

    @Test
    void testUnaryEndpointCodegenRejectsCompletionStageResponse() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import java.util.concurrent.CompletableFuture;
                        import java.util.concurrent.CompletionStage;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Unary("SayHello")
                            CompletionStage<String> sayHello(String request) {
                                return CompletableFuture.completedFuture(request.toUpperCase());
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Unary declarative gRPC method must not use "
                                          + "java.util.concurrent.CompletionStage "
                                          + "as a return type"));
    }

    @Test
    void testUnaryEndpointCodegenRejectsCompletableFutureResponseParameter() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import java.util.concurrent.CompletableFuture;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Unary("SayHello")
                            void sayHello(String request, CompletableFuture<String> response) {
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Unary declarative gRPC method must declare either "
                                          + "void method(RequestT request, StreamObserver<ResponseT> observer) or "
                                          + "ResponseT method(RequestT request)"));
    }

    @Test
    void testUnaryEndpointCodegenRejectsRawCompletionStageResponse() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import java.util.concurrent.CompletionStage;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Unary("SayHello")
                            CompletionStage sayHello(String request) {
                                return null;
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Unary declarative gRPC method must not use "
                                          + "java.util.concurrent.CompletionStage "
                                          + "as a return type"));
    }

    @Test
    void testUnaryEndpointCodegenRejectsCompletionStageResponseParameter() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import java.util.concurrent.CompletionStage;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Unary("SayHello")
                            void sayHello(String request, CompletionStage<String> response) {
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Unary declarative gRPC method must declare either "
                                          + "void method(RequestT request, StreamObserver<ResponseT> observer) or "
                                          + "ResponseT method(RequestT request)"));
    }

    @Test
    void testServerStreamingEndpointCodegenSupportsReturnedStream() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("StreamingEndpoint.java", """
                        package com.example;

                        import java.util.stream.Stream;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class StreamingEndpoint {
                            @RpcServer.ServerStreaming("Split")
                            Stream<String> split(String request) {
                                return Stream.of(request.split(" "));
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/StreamingEndpoint__GrpcRouteRegistration.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("ResponseHelper.stream(observer, endpoint.split(request))"));
    }

    @Test
    void testClientStreamingEndpointCodegenRejectsCompletableFutureParameter() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("StreamingEndpoint.java", """
                        package com.example;

                        import java.util.concurrent.CompletableFuture;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class StreamingEndpoint {
                            @RpcServer.ClientStreaming("Join")
                            StreamObserver<String> join(CompletableFuture<String> response) {
                                return null;
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Client streaming declarative gRPC method must declare "
                                          + "StreamObserver<RequestT> method(StreamObserver<ResponseT> observer)"));
    }

    @Test
    void testClientStreamingEndpointCodegenRejectsCompletionStageParameter() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("StreamingEndpoint.java", """
                        package com.example;

                        import java.util.concurrent.CompletionStage;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class StreamingEndpoint {
                            @RpcServer.ClientStreaming("Join")
                            StreamObserver<String> join(CompletionStage<String> response) {
                                return null;
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Client streaming declarative gRPC method must declare "
                                          + "StreamObserver<RequestT> method(StreamObserver<ResponseT> observer)"));
    }

    @Test
    void testStreamingEndpointCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("StreamingEndpoint.java", """
                        package com.example;

                        import com.google.protobuf.Descriptors;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class StreamingEndpoint {
                            @RpcServer.Proto
                            Descriptors.FileDescriptor proto() {
                                return null;
                            }

                            @RpcServer.ServerStreaming("Split")
                            void split(String request, StreamObserver<String> observer) {
                            }

                            @RpcServer.ClientStreaming("Join")
                            StreamObserver<String> join(StreamObserver<String> observer) {
                                return null;
                            }

                            @RpcServer.Bidirectional("Echo")
                            StreamObserver<String> echo(StreamObserver<String> observer) {
                                return null;
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/StreamingEndpoint__GrpcRouteRegistration.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("\"Split\""));
        assertThat(content, containsString("\"Join\""));
        assertThat(content, containsString("\"Echo\""));
        assertThat(content, containsString("entryPoints.serverStreaming("));
        assertThat(content, containsString("entryPoints.clientStreaming("));
        assertThat(content, containsString("entryPoints.bidirectional("));
    }

    @Test
    void testInterfaceMethodAnnotationCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterContract.java", """
                        package com.example;

                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

                        interface GreeterContract {
                            @RpcServer.Unary("SayHello")
                            void sayHello(String request, StreamObserver<String> observer);
                        }
                        """)
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import com.google.protobuf.Descriptors;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

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
                        import io.helidon.webserver.grpc.RpcServer;

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

                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        interface BrokenEndpoint {
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Interfaces should not be annotated with "
                                          + "io.helidon.webserver.grpc.RpcServer.Endpoint"));
    }

    @Test
    void testUnaryMethodSignatureRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("BrokenUnaryEndpoint.java", """
                        package com.example;

                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class BrokenUnaryEndpoint {
                            @RpcServer.Unary
                            void sayHello(String request) {
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Unary declarative gRPC method must declare either "
                                          + "void method(RequestT request, StreamObserver<ResponseT> observer) or "
                                          + "ResponseT "
                                          + "method(RequestT request)"));
    }

    @Test
    void testProtoMethodSignatureRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("BrokenProtoEndpoint.java", """
                        package com.example;

                        import com.google.protobuf.Descriptors;
                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Endpoint
                        class BrokenProtoEndpoint {
                            @RpcServer.Proto
                            Descriptors.FileDescriptor proto(String ignored) {
                                return null;
                            }

                            @RpcServer.Unary("SayHello")
                            void sayHello(String request, StreamObserver<String> observer) {
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Method annotated with @Proto must not declare parameters"));
    }

    @Test
    void testGrpcMarshallerAndInterceptorsCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Interceptors(ServiceInterceptor.class)
                        @RpcServer.Marshaller("java")
                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Unary("SayHello")
                            void sayHello(String request, StreamObserver<String> observer) {
                            }

                            @RpcServer.Unary("Ping")
                            @RpcServer.Marshaller("json")
                            @RpcServer.Interceptors(MethodInterceptor.class)
                            void ping(String request, StreamObserver<String> observer) {
                            }
                        }
                        """)
                .addSource("ServiceInterceptor.java", """
                        package com.example;

                        import io.helidon.service.registry.Service;

                        import io.grpc.Metadata;
                        import io.grpc.ServerCall;
                        import io.grpc.ServerCallHandler;
                        import io.grpc.ServerInterceptor;

                        @Service.Singleton
                        class ServiceInterceptor implements ServerInterceptor {
                            @Override
                            public <ReqT, ResT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, ResT> call,
                                                                                        Metadata headers,
                                                                                        ServerCallHandler<ReqT, ResT> next) {
                                return next.startCall(call, headers);
                            }
                        }
                        """)
                .addSource("MethodInterceptor.java", """
                        package com.example;

                        import io.helidon.service.registry.Service;

                        import io.grpc.Metadata;
                        import io.grpc.ServerCall;
                        import io.grpc.ServerCallHandler;
                        import io.grpc.ServerInterceptor;

                        @Service.Singleton
                        class MethodInterceptor implements ServerInterceptor {
                            @Override
                            public <ReqT, ResT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, ResT> call,
                                                                                        Metadata headers,
                                                                                        ServerCallHandler<ReqT, ResT> next) {
                                return next.startCall(call, headers);
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterEndpoint__GrpcRouteRegistration.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("@Service.Named(\"java\")"));
        assertThat(content, containsString("@Service.Named(\"json\")"));
        assertThat(content, containsString("descriptorBuilder.marshallerSupplier(marshallerSupplier_java);"));
        assertThat(content, containsString("descriptorBuilder.intercept(serverInterceptor_com_example_service_interceptor);"));
        assertThat(content, containsString(".marshallerSupplier(marshallerSupplier_json)"));
        assertThat(content, containsString(".intercept(serverInterceptor_com_example_method_interceptor)"));
    }

    @Test
    void testServerInterceptorWrongSideRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Interceptors(WrongSideInterceptor.class)
                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Unary
                            void sayHello(String request, StreamObserver<String> observer) {
                            }
                        }
                        """)
                .addSource("WrongSideInterceptor.java", """
                        package com.example;

                        import io.helidon.service.registry.Service;

                        import io.grpc.CallOptions;
                        import io.grpc.Channel;
                        import io.grpc.ClientCall;
                        import io.grpc.ClientInterceptor;
                        import io.grpc.MethodDescriptor;

                        @Service.Singleton
                        class WrongSideInterceptor implements ClientInterceptor {
                            @Override
                            public <ReqT, ResT> ClientCall<ReqT, ResT> interceptCall(MethodDescriptor<ReqT, ResT> method,
                                                                                     CallOptions callOptions,
                                                                                     Channel next) {
                                return next.newCall(method, callOptions);
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("must implement io.grpc.ServerInterceptor"));
    }

    @Test
    void testServerInterceptorMustBeService() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterEndpoint.java", """
                        package com.example;

                        import io.grpc.stub.StreamObserver;
                        import io.helidon.webserver.grpc.RpcServer;

                        @RpcServer.Interceptors(PlainInterceptor.class)
                        @RpcServer.Endpoint
                        class GreeterEndpoint {
                            @RpcServer.Unary
                            void sayHello(String request, StreamObserver<String> observer) {
                            }
                        }
                        """)
                .addSource("PlainInterceptor.java", """
                        package com.example;

                        import io.grpc.Metadata;
                        import io.grpc.ServerCall;
                        import io.grpc.ServerCallHandler;
                        import io.grpc.ServerInterceptor;

                        class PlainInterceptor implements ServerInterceptor {
                            @Override
                            public <ReqT, ResT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, ResT> call,
                                                                                        Metadata headers,
                                                                                        ServerCallHandler<ReqT, ResT> next) {
                                return next.startCall(call, headers);
                            }
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("must be a Helidon service registry service"));
    }
}
