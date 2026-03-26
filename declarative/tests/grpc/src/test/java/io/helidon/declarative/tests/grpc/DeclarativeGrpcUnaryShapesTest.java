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

import java.util.List;
import java.util.stream.Stream;

import io.helidon.service.registry.Lookup;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.ServiceRegistry;
import io.helidon.webclient.grpc.RpcClient;
import io.helidon.webserver.testing.junit5.ServerTest;

import com.google.protobuf.Empty;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@ExtendWith(GrpcTestEnvironmentExtension.class)
@ServerTest
class DeclarativeGrpcUnaryShapesTest {
    private final ServiceRegistry registry;

    DeclarativeGrpcUnaryShapesTest(ServiceRegistry registry) {
        this.registry = registry;
    }

    @BeforeEach
    void beforeEach() {
        UnaryShapesEndpoint.reset();
    }

    @Test
    void testUnaryDirectReturnShape() {
        TextMessages.TextMessage response = typedClient().directUpper(message("hello"));

        assertThat(response.getText(), is("DIRECT:HELLO"));
    }

    @Test
    void testUnaryNoRequestReturnShape() {
        TextMessages.TextMessage response = typedClient().noArgUpper();

        assertThat(response.getText(), is("NO_ARG:HELLO"));
    }

    @Test
    void testUnaryNoRequestObserverShape() {
        TextMessages.TextMessage response = typedClient().observerUpper();

        assertThat(response.getText(), is("OBSERVER:HELLO"));
    }

    @Test
    void testUnaryRequestNoResponseShape() {
        Empty response = typedClient().notify(message("hello"));

        assertThat(response, is(Empty.getDefaultInstance()));
        assertThat(UnaryShapesEndpoint.lastNotify(), is("HELLO"));
    }

    @Test
    void testUnaryNoRequestNoResponseShape() {
        Empty response = typedClient().ping();

        assertThat(response, is(Empty.getDefaultInstance()));
        assertThat(UnaryShapesEndpoint.pingCount(), is(1));
    }

    @Test
    void testServerStreamingNoRequestReturnShape() {
        assertThat(toTexts(typedClient().noArgSplit()), is(List.of("alpha", "beta")));
    }

    @Test
    void testServerStreamingNoRequestObserverShape() {
        assertThat(toTexts(typedClient().observerSplit()), is(List.of("observer", "stream")));
    }

    @Test
    void testServerStreamingNoRequestIterableReturnShape() {
        assertThat(toTexts(typedClient().iterableNoArgSplit()), is(List.of("iterable", "stream")));
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

    private static List<String> toTexts(Stream<TextMessages.TextMessage> messages) {
        try (messages) {
            return messages.map(TextMessages.TextMessage::getText)
                    .toList();
        }
    }
}
