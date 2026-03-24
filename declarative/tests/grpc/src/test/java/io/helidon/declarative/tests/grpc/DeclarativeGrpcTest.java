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

package io.helidon.declarative.tests.grpc;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import io.helidon.grpc.api.RpcClient;
import io.helidon.service.registry.Lookup;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.ServiceRegistry;
import io.helidon.webclient.grpc.GrpcClient;
import io.helidon.webclient.grpc.GrpcClientMethodDescriptor;
import io.helidon.webclient.grpc.GrpcServiceDescriptor;
import io.helidon.webserver.testing.junit5.ServerTest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;

@ServerTest
class DeclarativeGrpcTest {
    private static final GrpcServiceDescriptor SERVICE_DESCRIPTOR = GrpcServiceDescriptor.builder()
            .serviceName(TextServiceGrpc.SERVICE_NAME)
            .putMethod("Upper",
                       GrpcClientMethodDescriptor.unary(TextServiceGrpc.SERVICE_NAME, "Upper")
                               .requestType(TextMessages.TextMessage.class)
                               .responseType(TextMessages.TextMessage.class)
                               .build())
            .putMethod("Split",
                       GrpcClientMethodDescriptor.serverStreaming(TextServiceGrpc.SERVICE_NAME, "Split")
                               .requestType(TextMessages.TextMessage.class)
                               .responseType(TextMessages.TextMessage.class)
                               .build())
            .putMethod("Join",
                       GrpcClientMethodDescriptor.clientStreaming(TextServiceGrpc.SERVICE_NAME, "Join")
                               .requestType(TextMessages.TextMessage.class)
                               .responseType(TextMessages.TextMessage.class)
                               .build())
            .putMethod("Echo",
                       GrpcClientMethodDescriptor.bidirectional(TextServiceGrpc.SERVICE_NAME, "Echo")
                               .requestType(TextMessages.TextMessage.class)
                               .responseType(TextMessages.TextMessage.class)
                               .build())
            .build();

    private final GrpcClient client;
    private final ServiceRegistry registry;

    DeclarativeGrpcTest(GrpcClient client, ServiceRegistry registry) {
        this.client = client;
        this.registry = registry;
    }

    @BeforeEach
    void beforeEach() {
        SomeEntryPointInterceptor.reset();
    }

    @Test
    void testUnaryRoute() {
        TextMessages.TextMessage response = client.serviceClient(SERVICE_DESCRIPTOR)
                .unary("Upper", message("hello"));

        assertThat(response.getText(), is("HELLO"));
        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItem(startsWith(TextServiceEndpoint.class.getName() + ".upper(")));
    }

    @Test
    void testServerStreamingRoute() {
        Iterator<TextMessages.TextMessage> response = client.serviceClient(SERVICE_DESCRIPTOR)
                .serverStream("Split", message("hello world"));

        assertThat(toTexts(response), is(List.of("hello", "world")));
        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItem(startsWith(TextServiceEndpoint.class.getName() + ".split(")));
    }

    @Test
    void testClientStreamingRoute() {
        TextMessages.TextMessage response = client.serviceClient(SERVICE_DESCRIPTOR)
                .clientStream("Join", List.of(message("hello"), message("world")).iterator());

        assertThat(response.getText(), is("hello world"));
        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItem(startsWith(TextServiceEndpoint.class.getName() + ".join(")));
    }

    @Test
    void testBidirectionalRoute() {
        Iterator<TextMessages.TextMessage> response = client.serviceClient(SERVICE_DESCRIPTOR)
                .bidi("Echo", List.of(message("hello"), message("world")).iterator());

        assertThat(toTexts(response), is(List.of("hello", "world")));
        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItem(startsWith(TextServiceEndpoint.class.getName() + ".echo(")));
    }

    @Test
    void testTypedClient() {
        TextServiceClient typedClient = typedClient();

        TextMessages.TextMessage unary = typedClient.upper(message("hello"));
        assertThat(unary.getText(), is("HELLO"));

        Iterator<TextMessages.TextMessage> serverStreaming = typedClient.split(message("hello world"));
        assertThat(toTexts(serverStreaming), is(List.of("hello", "world")));

        TextMessages.TextMessage clientStreaming = typedClient.join(List.of(message("hello"), message("world")).iterator());
        assertThat(clientStreaming.getText(), is("hello world"));

        Iterator<TextMessages.TextMessage> bidirectional = typedClient.echo(List.of(message("hello"), message("world")).iterator());
        assertThat(toTexts(bidirectional), is(List.of("hello", "world")));

        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItems(startsWith(TextServiceEndpoint.class.getName() + ".upper("),
                            startsWith(TextServiceEndpoint.class.getName() + ".split("),
                            startsWith(TextServiceEndpoint.class.getName() + ".join("),
                            startsWith(TextServiceEndpoint.class.getName() + ".echo(")));
    }

    private static TextMessages.TextMessage message(String text) {
        return TextMessages.TextMessage.newBuilder()
                .setText(text)
                .build();
    }

    private TextServiceClient typedClient() {
        return registry.get(Lookup.builder()
                                    .addContract(TextServiceClient.class)
                                    .addQualifier(Qualifier.create(RpcClient.Client.class))
                                    .build());
    }

    private static List<String> toTexts(Iterator<TextMessages.TextMessage> messages) {
        List<String> result = new ArrayList<>();
        messages.forEachRemaining(message -> result.add(message.getText()));
        return result;
    }
}
