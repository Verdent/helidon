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
class DeclarativeGrpcClientStreamingShapesTest {
    private final ServiceRegistry registry;

    DeclarativeGrpcClientStreamingShapesTest(ServiceRegistry registry) {
        this.registry = registry;
    }

    @BeforeEach
    void beforeEach() {
        ClientStreamingShapesEndpoint.reset();
    }

    @Test
    void testClientStreamingIterableReturnShape() {
        TextMessages.TextMessage response = typedClient().joinIterable(List.of(message("hello"), message("world")));

        assertThat(response.getText(), is("ITERABLE:hello world"));
    }

    @Test
    void testClientStreamingIteratorReturnShape() {
        TextMessages.TextMessage response = typedClient().joinIterator(List.of(message("alpha"), message("beta")).iterator());

        assertThat(response.getText(), is("ITERATOR:alpha beta"));
    }

    @Test
    void testClientStreamingIterableEmptyResponseShape() {
        Empty response = typedClient().countIterable(List.of(message("one"), message("two")));

        assertThat(response, is(Empty.getDefaultInstance()));
        assertThat(ClientStreamingShapesEndpoint.iterableCount(), is(2));
    }

    @Test
    void testClientStreamingIteratorEmptyResponseShape() {
        Empty response = typedClient().countIterator(List.of(message("one"), message("two"), message("three")).iterator());

        assertThat(response, is(Empty.getDefaultInstance()));
        assertThat(ClientStreamingShapesEndpoint.iteratorCount(), is(3));
    }

    @Test
    void testClientStreamingStreamReturnShape() {
        TextMessages.TextMessage response = typedClient().joinStream(Stream.of(message("stream"), message("input")));

        assertThat(response.getText(), is("ITERABLE:stream input"));
    }

    @Test
    void testClientStreamingStreamEmptyResponseShape() {
        Empty response = typedClient().countStream(Stream.of(message("one"), message("two"), message("three"), message("four")));

        assertThat(response, is(Empty.getDefaultInstance()));
        assertThat(ClientStreamingShapesEndpoint.iterableCount(), is(4));
    }

    private ClientStreamingShapesClient typedClient() {
        return registry.get(Lookup.builder()
                                    .addContract(ClientStreamingShapesClient.class)
                                    .addQualifier(Qualifier.create(RpcClient.Client.class))
                                    .build());
    }

    private static TextMessages.TextMessage message(String text) {
        return TextMessages.TextMessage.newBuilder()
                .setText(text)
                .build();
    }
}
