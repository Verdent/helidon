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
            .serviceName(ConfiguredStringServiceEndpoint.CONFIGURED_SERVICE_NAME)
            .putMethod("Upper",
                       GrpcClientMethodDescriptor.unary(ConfiguredStringServiceEndpoint.CONFIGURED_SERVICE_NAME, "Upper")
                               .requestType(Strings.StringMessage.class)
                               .responseType(Strings.StringMessage.class)
                               .build())
            .build();

    private final GrpcClient configuredSocketClient;
    private final ServiceRegistry registry;

    DeclarativeGrpcConfigurationTest(@Socket(ConfiguredStringServiceEndpoint.SOCKET_NAME) GrpcClient configuredSocketClient,
                                     ServiceRegistry registry) {
        this.configuredSocketClient = configuredSocketClient;
        this.registry = registry;
    }

    @Test
    void testConfiguredServerRegistration() {
        GrpcRouteRegistration registration = registry.all(GrpcRouteRegistration.class)
                .stream()
                .filter(it -> it.socket().equals(ConfiguredStringServiceEndpoint.SOCKET_NAME))
                .findFirst()
                .orElseThrow();

        assertThat(registration.socket(), is(ConfiguredStringServiceEndpoint.SOCKET_NAME));
        assertThat(registration.socketRequired(), is(true));
        assertThat(registration.descriptor().fullName(), is(ConfiguredStringServiceEndpoint.CONFIGURED_SERVICE_NAME));
    }

    @Test
    void testConfiguredNamedClientSelection() {
        Strings.StringMessage directResponse = configuredSocketClient.serviceClient(SERVICE_DESCRIPTOR)
                .unary("Upper", message("hello"));
        assertThat(directResponse.getText(), is("CONFIGURED:HELLO"));

        ConfiguredStringServiceClient typedClient = registry.get(Lookup.builder()
                .addContract(ConfiguredStringServiceClient.class)
                .addQualifier(Qualifier.create(RpcClient.Client.class))
                .build());

        Strings.StringMessage typedResponse = typedClient.upper(message("hello"));
        assertThat(typedResponse.getText(), is("CONFIGURED:HELLO"));
    }

    private static Strings.StringMessage message(String text) {
        return Strings.StringMessage.newBuilder()
                .setText(text)
                .build();
    }
}
