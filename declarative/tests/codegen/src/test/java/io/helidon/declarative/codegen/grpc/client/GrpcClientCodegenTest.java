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

                        import io.helidon.grpc.api.RpcClient;

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
        assertThat(content, containsString("GrpcClientMethodDescriptor.unary(serviceName, \"SayHello\")"));
        assertThat(content, containsString("return serviceClient.unary(\"SayHello\", request);"));
    }

    @Test
    void testUnaryClientIteratorParameterRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("BrokenGreeterClient.java", """
                        package com.example;

                        import java.util.Iterator;

                        import io.helidon.grpc.api.RpcClient;

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
                   containsString("Declarative gRPC unary client request parameter must not be an iterator or"
                                          + " stream observer"));
    }

    @Test
    void testMultipleClientMethodAnnotationsRejected() {
        var result = GrpcCodegenTestSupport.compilerBuilder()
                .addSource("BrokenAnnotatedClient.java", """
                        package com.example;

                        import java.util.Iterator;

                        import io.helidon.grpc.api.RpcClient;

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
}
