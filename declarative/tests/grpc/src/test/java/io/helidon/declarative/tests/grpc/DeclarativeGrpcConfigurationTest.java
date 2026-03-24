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

import java.lang.reflect.Field;
import java.time.Duration;

import io.helidon.config.Config;
import io.helidon.webclient.grpc.RpcClient;
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
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

@ExtendWith(GrpcTestEnvironmentExtension.class)
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
    private final Config config;
    private final ServiceRegistry registry;

    DeclarativeGrpcConfigurationTest(@Socket(ConfiguredTextServiceEndpoint.SOCKET_NAME) GrpcClient configuredSocketClient,
                                     Config config,
                                     ServiceRegistry registry) {
        this.configuredSocketClient = configuredSocketClient;
        this.config = config;
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
        assertThat(registration.descriptor().proto(), nullValue());
    }

    @Test
    void testConfiguredNamedClientSelection() {
        TextMessages.TextMessage directResponse = configuredSocketClient.serviceClient(SERVICE_DESCRIPTOR)
                .unary("Upper", message("hello"));
        assertThat(directResponse.getText(), is("CONFIGURED:HELLO"));

        ConfiguredTextServiceClient typedClient = typedClient(ConfiguredTextServiceClient.class);

        TextMessages.TextMessage typedResponse = typedClient.upper(message("hello"));
        assertThat(typedResponse.getText(), is("CONFIGURED:HELLO"));
    }

    @Test
    void testDefaultClientSelection() {
        DefaultTextServiceClient typedClient = typedClient(DefaultTextServiceClient.class);

        TextMessages.TextMessage typedResponse = typedClient.upper(message("hello"));
        assertThat(typedResponse.getText(), is("HELLO"));
    }

    @Test
    void testConfiguredClientSubtreeSelection() throws ReflectiveOperationException {
        ConfigBackedTextServiceClient typedClient = typedClient(ConfigBackedTextServiceClient.class);

        TextMessages.TextMessage typedResponse = typedClient.upper(message("hello"));
        assertThat(typedResponse.getText(), is("CONFIGURED:HELLO"));

        GrpcClient underlyingClient = generatedClient(typedClient);
        assertThat(underlyingClient.clientConfig().protocolConfig().pollWaitTime(), is(Duration.ofSeconds(1)));
        assertThat(underlyingClient.clientConfig().baseUri().orElseThrow().toString(),
                   containsString(config.get("test.server.socket." + ConfiguredTextServiceEndpoint.SOCKET_NAME + ".port")
                                          .asString()
                                          .orElseThrow()));
    }

    private static TextMessages.TextMessage message(String text) {
        return TextMessages.TextMessage.newBuilder()
                .setText(text)
                .build();
    }

    private <T> T typedClient(Class<T> type) {
        return registry.get(Lookup.builder()
                .addContract(type)
                .addQualifier(Qualifier.create(RpcClient.Client.class))
                .build());
    }

    private static GrpcClient generatedClient(Object typedClient) throws ReflectiveOperationException {
        Field clientField = typedClient.getClass().getDeclaredField("client");
        clientField.setAccessible(true);
        return (GrpcClient) clientField.get(typedClient);
    }
}
