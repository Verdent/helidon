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

import io.helidon.grpc.api.RpcClient;
import io.helidon.service.registry.Lookup;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.ServiceRegistry;
import io.helidon.webclient.grpc.GrpcClient;
import io.helidon.webclient.grpc.GrpcClientMethodDescriptor;
import io.helidon.webclient.grpc.GrpcServiceDescriptor;
import io.helidon.webserver.grpc.GrpcRouteRegistration;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.Socket;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@ServerTest
class DeclarativeGrpcConfigurationTest {
    private static final GrpcServiceDescriptor SERVICE_DESCRIPTOR = GrpcServiceDescriptor.builder()
            .serviceName(ConfiguredTextServiceEndpoint.CONFIGURED_SERVICE_NAME)
            .putMethod("Upper",
                       GrpcClientMethodDescriptor.unary(ConfiguredTextServiceEndpoint.CONFIGURED_SERVICE_NAME, "Upper")
                               .requestType(TextMessages.TextMessage.class)
                               .responseType(TextMessages.TextMessage.class)
                               .build())
            .build();

    private final GrpcClient configuredSocketClient;
    private final ServiceRegistry registry;

    DeclarativeGrpcConfigurationTest(@Socket(ConfiguredTextServiceEndpoint.SOCKET_NAME) GrpcClient configuredSocketClient,
                                     ServiceRegistry registry) {
        this.configuredSocketClient = configuredSocketClient;
        this.registry = registry;
    }

    @Test
    void testConfiguredServerRegistration() {
        GrpcRouteRegistration registration = registry.all(GrpcRouteRegistration.class)
                .stream()
                .filter(it -> it.socket().equals(ConfiguredTextServiceEndpoint.SOCKET_NAME))
                .findFirst()
                .orElseThrow();

        assertThat(registration.socket(), is(ConfiguredTextServiceEndpoint.SOCKET_NAME));
        assertThat(registration.socketRequired(), is(true));
        assertThat(registration.descriptor().fullName(), is(ConfiguredTextServiceEndpoint.CONFIGURED_SERVICE_NAME));
    }

    @Test
    void testConfiguredNamedClientSelection() {
        TextMessages.TextMessage directResponse = configuredSocketClient.serviceClient(SERVICE_DESCRIPTOR)
                .unary("Upper", message("hello"));
        assertThat(directResponse.getText(), is("CONFIGURED:HELLO"));

        ConfiguredTextServiceClient typedClient = registry.get(Lookup.builder()
                .addContract(ConfiguredTextServiceClient.class)
                .addQualifier(Qualifier.create(RpcClient.Client.class))
                .build());

        TextMessages.TextMessage typedResponse = typedClient.upper(message("hello"));
        assertThat(typedResponse.getText(), is("CONFIGURED:HELLO"));
    }

    private static TextMessages.TextMessage message(String text) {
        return TextMessages.TextMessage.newBuilder()
                .setText(text)
                .build();
    }
}
