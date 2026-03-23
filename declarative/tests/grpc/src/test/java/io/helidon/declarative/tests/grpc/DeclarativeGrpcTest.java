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

import io.helidon.webclient.grpc.GrpcClient;
import io.helidon.webclient.grpc.GrpcClientMethodDescriptor;
import io.helidon.webclient.grpc.GrpcServiceDescriptor;
import io.helidon.webserver.testing.junit5.ServerTest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.hasItem;
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
            .build();

    private final GrpcClient client;

    DeclarativeGrpcTest(GrpcClient client) {
        this.client = client;
    }

    @BeforeEach
    void beforeEach() {
        SomeEntryPointInterceptor.reset();
    }

    @Test
    void testUnaryRoute() {
        Strings.StringMessage response = client.serviceClient(SERVICE_DESCRIPTOR)
                .unary("Upper", Strings.StringMessage.newBuilder().setText("hello").build());

        assertThat(response.getText(), is("HELLO"));
        assertThat(SomeEntryPointInterceptor.executions(),
                   hasItem(startsWith(StringServiceEndpoint.class.getName() + ".upper(")));
    }
}
