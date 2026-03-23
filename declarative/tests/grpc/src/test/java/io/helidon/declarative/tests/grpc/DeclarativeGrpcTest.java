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
            .serviceName(StringServiceGrpc.SERVICE_NAME)
            .putMethod("Upper",
                       GrpcClientMethodDescriptor.unary(StringServiceGrpc.SERVICE_NAME, "Upper")
                               .requestType(Strings.StringMessage.class)
                               .responseType(Strings.StringMessage.class)
                               .build())
            .putMethod("Split",
                       GrpcClientMethodDescriptor.serverStreaming(StringServiceGrpc.SERVICE_NAME, "Split")
                               .requestType(Strings.StringMessage.class)
                               .responseType(Strings.StringMessage.class)
                               .build())
            .putMethod("Join",
                       GrpcClientMethodDescriptor.clientStreaming(StringServiceGrpc.SERVICE_NAME, "Join")
                               .requestType(Strings.StringMessage.class)
                               .responseType(Strings.StringMessage.class)
                               .build())
            .putMethod("Echo",
                       GrpcClientMethodDescriptor.bidirectional(StringServiceGrpc.SERVICE_NAME, "Echo")
                               .requestType(Strings.StringMessage.class)
                               .responseType(Strings.StringMessage.class)
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
        Strings.StringMessage response = client.serviceClient(SERVICE_DESCRIPTOR)
                .unary("Upper", message("hello"));

        assertThat(response.getText(), is("HELLO"));
        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItem(startsWith(StringServiceEndpoint.class.getName() + ".upper(")));
    }

    @Test
    void testServerStreamingRoute() {
        Iterator<Strings.StringMessage> response = client.serviceClient(SERVICE_DESCRIPTOR)
                .serverStream("Split", message("hello world"));

        assertThat(toTexts(response), is(List.of("hello", "world")));
        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItem(startsWith(StringServiceEndpoint.class.getName() + ".split(")));
    }

    @Test
    void testClientStreamingRoute() {
        Strings.StringMessage response = client.serviceClient(SERVICE_DESCRIPTOR)
                .clientStream("Join", List.of(message("hello"), message("world")).iterator());

        assertThat(response.getText(), is("hello world"));
        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItem(startsWith(StringServiceEndpoint.class.getName() + ".join(")));
    }

    @Test
    void testBidirectionalRoute() {
        Iterator<Strings.StringMessage> response = client.serviceClient(SERVICE_DESCRIPTOR)
                .bidi("Echo", List.of(message("hello"), message("world")).iterator());

        assertThat(toTexts(response), is(List.of("hello", "world")));
        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItem(startsWith(StringServiceEndpoint.class.getName() + ".echo(")));
    }

    @Test
    void testTypedClient() {
        StringServiceClient typedClient = typedClient();

        Strings.StringMessage unary = typedClient.upper(message("hello"));
        assertThat(unary.getText(), is("HELLO"));

        Iterator<Strings.StringMessage> serverStreaming = typedClient.split(message("hello world"));
        assertThat(toTexts(serverStreaming), is(List.of("hello", "world")));

        Strings.StringMessage clientStreaming = typedClient.join(List.of(message("hello"), message("world")).iterator());
        assertThat(clientStreaming.getText(), is("hello world"));

        Iterator<Strings.StringMessage> bidirectional = typedClient.echo(List.of(message("hello"), message("world")).iterator());
        assertThat(toTexts(bidirectional), is(List.of("hello", "world")));

        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItems(startsWith(StringServiceEndpoint.class.getName() + ".upper("),
                            startsWith(StringServiceEndpoint.class.getName() + ".split("),
                            startsWith(StringServiceEndpoint.class.getName() + ".join("),
                            startsWith(StringServiceEndpoint.class.getName() + ".echo(")));
    }

    private static Strings.StringMessage message(String text) {
        return Strings.StringMessage.newBuilder()
                .setText(text)
                .build();
    }

    private StringServiceClient typedClient() {
        return registry.get(Lookup.builder()
                                    .addContract(StringServiceClient.class)
                                    .addQualifier(Qualifier.create(RpcClient.Client.class))
                                    .build());
    }

    private static List<String> toTexts(Iterator<Strings.StringMessage> messages) {
        List<String> result = new ArrayList<>();
        messages.forEachRemaining(message -> result.add(message.getText()));
        return result;
    }
}
