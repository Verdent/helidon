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

import io.helidon.service.registry.Lookup;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.ServiceRegistry;
import io.helidon.webclient.grpc.RpcClient;
import io.helidon.webserver.testing.junit5.ServerTest;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(GrpcTestEnvironmentExtension.class)
@ServerTest
class DeclarativeGrpcUnaryShapesTest {
    private final ServiceRegistry registry;

    DeclarativeGrpcUnaryShapesTest(ServiceRegistry registry) {
        this.registry = registry;
    }

    @Test
    void testUnaryDirectReturnShape() {
        TextMessages.TextMessage response = typedClient().directUpper(message("hello"));

        assertThat(response.getText(), is("DIRECT:HELLO"));
    }

    @Test
    void testUnaryCompletionStageReturnShape() {
        TextMessages.TextMessage response = typedClient().stageUpper(message("hello"));

        assertThat(response.getText(), is("STAGE:HELLO"));
    }

    @Test
    void testUnaryFutureResponseParameterShape() {
        TextMessages.TextMessage response = typedClient().futureUpper(message("hello"));

        assertThat(response.getText(), is("FUTURE:HELLO"));
    }

    @Test
    void testUnaryFutureResponseParameterFailure() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class,
                                                       () -> typedClient().futureFail(message("boom")));

        assertThat(exception.getStatus().getCode(), is(Status.Code.UNKNOWN));
    }

    private UnaryShapesClient typedClient() {
        return registry.get(Lookup.builder()
                                    .addContract(UnaryShapesClient.class)
                                    .addQualifier(Qualifier.create(RpcClient.Client.class))
                                    .build());
    }

    private static TextMessages.TextMessage message(String text) {
        return TextMessages.TextMessage.newBuilder()
                .setText(text)
                .build();
    }
}
