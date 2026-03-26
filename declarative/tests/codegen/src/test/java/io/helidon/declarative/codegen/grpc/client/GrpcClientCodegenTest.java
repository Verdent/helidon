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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import io.helidon.declarative.codegen.grpc.GrpcCodegenTestSupport;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class GrpcClientCodegenTest {
    @Test
    void testUnaryClientCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterClient.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint("http://localhost:8080")
                        @RpcClient.ServiceName("example.Greeter")
                        interface GreeterClient {
                            @RpcClient.Unary("SayHello")
                            String sayHello(String request);
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterClient__GrpcClient.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("class GreeterClient__GrpcClient implements GreeterClient"));
        assertThat(content, containsString("var endpointConfig = config.get(\"com.example.GreeterClient\");"));
        assertThat(content, containsString("GrpcClientMethodDescriptor.unary(serviceName, \"SayHello\")"));
        assertThat(content, containsString("return serviceClient.unary(\"SayHello\", request);"));
    }

    @Test
    void testNoRequestClientCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterClient.java", """
                        package com.example;

                        import java.util.Iterator;
                        import java.util.stream.Stream;
                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint("http://localhost:8080")
                        interface GreeterClient {
                            @RpcClient.Unary("Ping")
                            String ping();

                            @RpcClient.ServerStreaming("Split")
                            Iterator<String> split();

                            @RpcClient.ServerStreaming("SplitStream")
                            Stream<String> splitStream();
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterClient__GrpcClient.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("GrpcClientMethodDescriptor.unary(serviceName, \"Ping\")"));
        assertThat(content, containsString(".requestType(Empty.class).responseType(String.class)"));
        assertThat(content, containsString("return serviceClient.unary(\"Ping\", Empty.getDefaultInstance());"));
        assertThat(content, containsString("GrpcClientMethodDescriptor.serverStreaming(serviceName, \"Split\")"));
        assertThat(content, containsString("return serviceClient.serverStream(\"Split\", Empty.getDefaultInstance());"));
        assertThat(content, containsString("GrpcClientMethodDescriptor.serverStreaming(serviceName, \"SplitStream\")"));
        assertThat(content,
                   containsString("return java.util.stream.StreamSupport.stream("
                                          + "java.util.Spliterators.spliteratorUnknownSize("
                                          + "serviceClient.serverStream(\"SplitStream\", Empty.getDefaultInstance()),"
                                          + " java.util.Spliterator.ORDERED), false);"));
    }

    @Test
    void testStreamingClientCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("StreamingClient.java", """
                        package com.example;

                        import java.util.Iterator;
                        import java.util.stream.Stream;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint("http://localhost:8080")
                        interface StreamingClient {
                            @RpcClient.ServerStreaming("Split")
                            Iterator<String> split(String request);

                            @RpcClient.ServerStreaming("SplitStream")
                            Stream<String> splitStream(String request);

                            @RpcClient.ClientStreaming("Join")
                            String join(Iterable<String> request);

                            @RpcClient.ClientStreaming("JoinStream")
                            String joinStream(Stream<String> request);

                            @RpcClient.Bidirectional("Echo")
                            Iterator<String> echo(Iterator<String> request);
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/StreamingClient__GrpcClient.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("GrpcClientMethodDescriptor.serverStreaming(serviceName, \"Split\")"));
        assertThat(content, containsString("return serviceClient.serverStream(\"Split\", request);"));
        assertThat(content, containsString("GrpcClientMethodDescriptor.serverStreaming(serviceName, \"SplitStream\")"));
        assertThat(content,
                   containsString("return java.util.stream.StreamSupport.stream("
                                          + "java.util.Spliterators.spliteratorUnknownSize("
                                          + "serviceClient.serverStream(\"SplitStream\", request),"
                                          + " java.util.Spliterator.ORDERED), false);"));
        assertThat(content, containsString("GrpcClientMethodDescriptor.clientStreaming(serviceName, \"Join\")"));
        assertThat(content, containsString("return serviceClient.clientStream(\"Join\", request.iterator());"));
        assertThat(content, containsString("GrpcClientMethodDescriptor.clientStreaming(serviceName, \"JoinStream\")"));
        assertThat(content, containsString("try (var requestStream = request) {"));
        assertThat(content, containsString("return serviceClient.clientStream(\"JoinStream\", requestStream.iterator());"));
        assertThat(content, containsString("GrpcClientMethodDescriptor.bidirectional(serviceName, \"Echo\")"));
        assertThat(content, containsString("return serviceClient.bidi(\"Echo\", request);"));
    }

    @Test
    void testInheritedClientMethodCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterContract.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        interface GreeterContract {
                            @RpcClient.Unary("SayHello")
                            String sayHello(String request);
                        }
                        """)
                .addSource("GreeterClient.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint("http://localhost:8080")
                        interface GreeterClient extends GreeterContract {
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterClient__GrpcClient.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("GrpcClientMethodDescriptor.unary(serviceName, \"SayHello\")"));
        assertThat(content, containsString("return serviceClient.unary(\"SayHello\", request);"));
    }

    @Test
    void testUnaryClientMethodNameDefaultsToJavaName() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterClient.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint("http://localhost:8080")
                        interface GreeterClient {
                            @RpcClient.Unary
                            String sayHello(String request);
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterClient__GrpcClient.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("serviceName = \"GreeterClient\";"));
        assertThat(content, containsString("GrpcClientMethodDescriptor.unary(serviceName, \"sayHello\")"));
        assertThat(content, containsString("return serviceClient.unary(\"sayHello\", request);"));
    }

    @Test
    void testStaticNamedClientUsesInjectedSupplier() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterClient.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint(value = "http://localhost:8080", clientName = "greeter")
                        interface GreeterClient {
                            @RpcClient.Unary
                            String sayHello(String request);
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterClient__GrpcClient.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("namedClientSupplier.get().orElse(null);"));
        assertThat(content, containsString("clientSupplier.get().orElse(null);"));
        assertThat(content.contains("registry.supplyFirst("), is(false));
    }

    @Test
    void testDynamicNamedClientRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterClient.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint(value = "http://localhost:8080",
                                            clientName = "${greeter.client.name:greeter}")
                        interface GreeterClient {
                            @RpcClient.Unary
                            String sayHello(String request);
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Declarative gRPC client clientName must be a static service registry name"
                                          + " and does not support configuration expressions"));
    }

    @Test
    void testConfigBackedClientCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterClient.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint(value = "http://localhost:8080", configKey = "greeter-client")
                        interface GreeterClient {
                            @RpcClient.Unary
                            String sayHello(String request);
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterClient__GrpcClient.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("var endpointConfig = config.get(\"greeter-client\");"));
        assertThat(content, containsString("var clientUri = uri;"));
        assertThat(content, containsString("var clientConfig = endpointConfig.get(\"client\");"));
        assertThat(content, containsString("GrpcClientConfig.create(clientConfig)"));
        assertThat(content, containsString(".config(clientConfig).baseUri(clientUri)"));
    }

    @Test
    void testUnaryClientIteratorParameterRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("BrokenGreeterClient.java", """
                        package com.example;

                        import java.util.Iterator;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint("http://localhost:8080")
                        interface BrokenGreeterClient {
                            @RpcClient.Unary
                            String sayHello(Iterator<String> request);
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("Declarative gRPC unary client request parameter must not be an iterator,"
                                          + " stream, or stream observer"));
    }

    @Test
    void testMultipleClientMethodAnnotationsRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("BrokenAnnotatedClient.java", """
                        package com.example;

                        import java.util.Iterator;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Endpoint("http://localhost:8080")
                        interface BrokenAnnotatedClient {
                            @RpcClient.Unary
                            @RpcClient.ServerStreaming
                            Iterator<String> sayHello(String request);
                        }
                        """)
                .build()
                .compile();

        assertThat(result.success(), is(false));
        assertThat(GrpcCodegenTestSupport.diagnostics(result),
                   containsString("must have exactly one RpcClient method annotation"));
    }

    @Test
    void testGrpcMarshallerAndInterceptorsCodegen() throws IOException {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterClient.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Interceptors(ServiceInterceptor.class)
                        @RpcClient.Marshaller("java")
                        @RpcClient.Endpoint("http://localhost:8080")
                        interface GreeterClient {
                            @RpcClient.Unary("SayHello")
                            String sayHello(String request);

                            @RpcClient.Unary("Ping")
                            @RpcClient.Marshaller("json")
                            @RpcClient.Interceptors(MethodInterceptor.class)
                            String ping(String request);
                        }
                        """)
                .addSource("ServiceInterceptor.java", """
                        package com.example;

                        import io.helidon.service.registry.Service;

                        import io.grpc.CallOptions;
                        import io.grpc.Channel;
                        import io.grpc.ClientCall;
                        import io.grpc.ClientInterceptor;
                        import io.grpc.MethodDescriptor;

                        @Service.Singleton
                        class ServiceInterceptor implements ClientInterceptor {
                            @Override
                            public <ReqT, ResT> ClientCall<ReqT, ResT> interceptCall(MethodDescriptor<ReqT, ResT> method,
                                                                                     CallOptions callOptions,
                                                                                     Channel next) {
                                return next.newCall(method, callOptions);
                            }
                        }
                        """)
                .addSource("MethodInterceptor.java", """
                        package com.example;

                        import io.helidon.service.registry.Service;

                        import io.grpc.CallOptions;
                        import io.grpc.Channel;
                        import io.grpc.ClientCall;
                        import io.grpc.ClientInterceptor;
                        import io.grpc.MethodDescriptor;

                        @Service.Singleton
                        class MethodInterceptor implements ClientInterceptor {
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

        assertThat(result.success(), is(true));

        var generated = result.sourceOutput().resolve("com/example/GreeterClient__GrpcClient.java");
        assertThat(Files.exists(generated), is(true));

        String content = Files.readString(generated, StandardCharsets.UTF_8);
        assertThat(content, containsString("@Service.Named(\"java\")"));
        assertThat(content, containsString("@Service.Named(\"json\")"));
        assertThat(content, containsString(".addInterceptor(clientInterceptor_com_example_service_interceptor)"));
        assertThat(content, containsString(".marshallerSupplier(marshallerSupplier_java)"));
        assertThat(content, containsString(".marshallerSupplier(marshallerSupplier_json)"));
        assertThat(content, containsString(".intercept(clientInterceptor_com_example_method_interceptor)"));
    }

    @Test
    void testClientInterceptorWrongSideRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterClient.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Interceptors(WrongSideInterceptor.class)
                        @RpcClient.Endpoint("http://localhost:8080")
                        interface GreeterClient {
                            @RpcClient.Unary
                            String sayHello(String request);
                        }
                        """)
                .addSource("WrongSideInterceptor.java", """
                        package com.example;

                        import io.helidon.service.registry.Service;

                        import io.grpc.Metadata;
                        import io.grpc.ServerCall;
                        import io.grpc.ServerCallHandler;
                        import io.grpc.ServerInterceptor;

                        @Service.Singleton
                        class WrongSideInterceptor implements ServerInterceptor {
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
                   containsString("must implement io.grpc.ClientInterceptor"));
    }

    @Test
    void testClientInterceptorMustBeService() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("GreeterClient.java", """
                        package com.example;

                        import io.helidon.webclient.grpc.RpcClient;

                        @RpcClient.Interceptors(PlainInterceptor.class)
                        @RpcClient.Endpoint("http://localhost:8080")
                        interface GreeterClient {
                            @RpcClient.Unary
                            String sayHello(String request);
                        }
                        """)
                .addSource("PlainInterceptor.java", """
                        package com.example;

                        import io.grpc.CallOptions;
                        import io.grpc.Channel;
                        import io.grpc.ClientCall;
                        import io.grpc.ClientInterceptor;
                        import io.grpc.MethodDescriptor;

                        class PlainInterceptor implements ClientInterceptor {
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
                   containsString("must be a Helidon service registry service"));
    }
}
