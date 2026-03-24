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

package io.helidon.webclient.grpc.tests;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import io.helidon.common.configurable.Resource;
import io.helidon.common.tls.Tls;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.grpc.GrpcClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.testing.junit5.ServerTest;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ServerTest
class GrpcInteropComplianceTest extends GrpcBaseTest {
    private static final long TIMEOUT_SECONDS = 10;

    private static final Metadata.Key<String> GRPC_ENCODING =
            Metadata.Key.of("grpc-encoding", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> GRPC_ACCEPT_ENCODING =
            Metadata.Key.of("grpc-accept-encoding", Metadata.ASCII_STRING_MARSHALLER);

    private final Channel channel;

    GrpcInteropComplianceTest(WebServer server) {
        Tls clientTls = Tls.builder()
                .trust(trust -> trust
                        .keystore(store -> store
                                .passphrase("password")
                                .trustStore(true)
                                .keystore(Resource.create("client.p12"))))
                .build();
        WebClient webClient = WebClient.builder()
                .tls(clientTls)
                .baseUri("https://localhost:" + server.port())
                .build();
        this.channel = webClient.client(GrpcClient.PROTOCOL).channel();
    }

    @Test
    void testUnaryCustomMetadataRoundTrip() throws InterruptedException {
        // Spec note: upstream interop case "custom_metadata" verifies ASCII and
        // binary metadata survive a unary round-trip, including trailer values.
        Metadata metadata = requestMetadata();

        CallResult<Strings.StringMessage> result = unaryCall(StringServiceGrpc.getUpperMethod(),
                                                             metadata,
                                                             newStringMessage("hello"));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.headers(), notNullValue());
        assertThat(result.headers().get(INITIAL_METADATA_KEY), is("initial-metadata"));
        assertThat(new String(result.trailers().get(TRAILING_METADATA_KEY), StandardCharsets.UTF_8), is("ab"));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().get(0).getText(), is("HELLO"));
    }

    @Test
    void testBidirectionalCustomMetadataRoundTrip() throws InterruptedException {
        // Spec note: upstream interop case "custom_metadata" also applies to
        // streaming RPCs, including binary trailer metadata.
        Metadata metadata = requestMetadata();

        CallResult<Strings.StringMessage> result = streamingCall(StringServiceGrpc.getEchoMethod(),
                                                                 metadata,
                                                                 List.of(newStringMessage("hello"),
                                                                         newStringMessage("world")));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.headers(), notNullValue());
        assertThat(result.headers().get(INITIAL_METADATA_KEY), is("initial-metadata"));
        assertThat(new String(result.trailers().get(TRAILING_METADATA_KEY), StandardCharsets.UTF_8), is("ab"));
        assertThat(result.messages().size(), is(2));
        assertThat(result.messages().get(0).getText(), is("hello"));
        assertThat(result.messages().get(1).getText(), is("world"));
    }

    @Test
    void testEmptyUnaryPayloadRoundTrip() throws InterruptedException {
        // Spec note: upstream interop case "empty_unary" verifies a unary RPC
        // can carry an empty protobuf payload and still complete with OK status.
        CallResult<Strings.StringMessage> result = unaryCall(StringServiceGrpc.getUpperMethod(),
                                                             new Metadata(),
                                                             Strings.StringMessage.getDefaultInstance());

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().getFirst().getText(), is(""));
    }

    @Test
    void testLargeUnaryPayloadSpanningMultipleHttp2Frames() throws InterruptedException {
        // Spec note: upstream interop case "large_unary" validates that one gRPC
        // message may span multiple HTTP/2 DATA frames but still decode as a
        // single protobuf message.
        String requestText = "grpc".repeat(32 * 1024);

        CallResult<Strings.StringMessage> result = unaryCall(StringServiceGrpc.getUpperMethod(),
                                                             new Metadata(),
                                                             newStringMessage(requestText));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().getFirst().getText(), is(requestText.toUpperCase(Locale.ROOT)));
    }

    @Test
    void testUnaryStatusCodeAndMessage() {
        // Spec note: upstream interop case "status_code_and_message" requires
        // grpc-status and grpc-message to surface as the final RPC status.
        StringServiceGrpc.StringServiceBlockingStub service = StringServiceGrpc.newBlockingStub(channel);

        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class,
                                                        () -> service.badMethod(newStringMessage("bad request")));

        assertThat(exception.getStatus().getCode(), is(Status.Code.INVALID_ARGUMENT));
        assertThat(exception.getStatus().getDescription(), is("bad request"));
    }

    @Test
    void testSpecialStatusMessageRoundTrip() {
        // Spec note: PROTOCOL-HTTP2 percent-encodes grpc-message bytes outside
        // the visible ASCII range; the client must decode them losslessly.
        StringServiceGrpc.StringServiceBlockingStub service = StringServiceGrpc.newBlockingStub(channel);
        String statusMessage = "Bad input % \n and unicode \u00A9";

        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class,
                                                        () -> service.badMethod(newStringMessage(statusMessage)));

        assertThat(exception.getStatus().getCode(), is(Status.Code.INVALID_ARGUMENT));
        assertThat(exception.getStatus().getDescription(), is(statusMessage));
    }

    @Test
    void testBidirectionalStatusCodeAndMessage() throws InterruptedException {
        // Spec note: upstream interop case "status_code_and_message" also applies
        // when the final status is delivered after streaming responses.
        String statusMessage = "stream failure \u00A9";

        CallResult<Strings.StringMessage> result = streamingCall(StringServiceGrpc.getEchoMethod(),
                                                                 new Metadata(),
                                                                 List.of(newStringMessage("hello"),
                                                                         newStringMessage(
                                                                                 ERROR_PREFIX + statusMessage)));

        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().get(0).getText(), is("hello"));
        assertThat(result.status().getCode(), is(Status.Code.INVALID_ARGUMENT));
        assertThat(result.status().getDescription(), is(statusMessage));
    }

    @Test
    void testPingPongStreamingPreservesMessageOrder() throws InterruptedException {
        // Spec note: upstream interop case "ping_pong" verifies bidi calls can
        // alternate writes and reads while preserving message order.
        RecordingListener<Strings.StringMessage> listener = new RecordingListener<>();
        ClientCall<Strings.StringMessage, Strings.StringMessage> call =
                channel.newCall(StringServiceGrpc.getEchoMethod(), CallOptions.DEFAULT);

        call.start(listener, new Metadata());

        call.request(1);
        call.sendMessage(newStringMessage("one"));
        listener.awaitMessages(1);
        assertThat(texts(listener.messages()), contains("one"));

        call.request(1);
        call.sendMessage(newStringMessage("two"));
        listener.awaitMessages(2);
        assertThat(texts(listener.messages()), contains("one", "two"));

        call.request(1);
        call.sendMessage(newStringMessage("three"));
        listener.awaitMessages(3);
        call.halfClose();

        CallResult<Strings.StringMessage> result = listener.await();

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(texts(result.messages()), contains("one", "two", "three"));
    }

    @Test
    void testMissingMethodReturnsUnimplemented() throws InterruptedException {
        // Spec note: upstream interop case "unimplemented_method" requires an
        // unknown method to close with grpc-status UNIMPLEMENTED.
        CallResult<Strings.StringMessage> result = unaryCall(missingUnaryMethod("StringService", "MissingMethod"),
                                                             new Metadata(),
                                                             newStringMessage("hello"));

        assertThat(result.status().getCode(), is(Status.Code.UNIMPLEMENTED));
        assertThat(result.headers(), nullValue());
    }

    @Test
    void testMissingServiceReturnsUnimplemented() throws InterruptedException {
        // Spec note: upstream interop case "unimplemented_service" requires an
        // unknown service to close with grpc-status UNIMPLEMENTED.
        CallResult<Strings.StringMessage> result = unaryCall(missingUnaryMethod("MissingService", "Upper"),
                                                             new Metadata(),
                                                             newStringMessage("hello"));

        assertThat(result.status().getCode(), is(Status.Code.UNIMPLEMENTED));
        assertThat(result.headers(), nullValue());
    }

    @Test
    void testCompressedResponseRoundTrip() throws InterruptedException {
        // Spec note: upstream interop case "server_compressed_unary" verifies a
        // client advertises supported encodings, accepts a compressed response,
        // and still receives the original message payload.
        CallResult<Strings.StringMessage> result = unaryCall(StringServiceGrpc.getUpperMethod(),
                                                             new Metadata(),
                                                             newStringMessage("hello"));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.headers().get(GRPC_ENCODING), is("gzip"));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().getFirst().getText(), is("HELLO"));
    }

    @Test
    void testUnsupportedCompressionAdvertisesSupportedEncodings() throws InterruptedException {
        // Spec note: PROTOCOL-HTTP2 requires unsupported grpc-encoding values to
        // fail with UNIMPLEMENTED and advertise supported encodings.
        Metadata metadata = new Metadata();
        metadata.put(GRPC_ENCODING, "snappy");

        CallResult<Strings.StringMessage> result = unaryCall(StringServiceGrpc.getUpperMethod(),
                                                             metadata,
                                                             newStringMessage("hello"));

        assertThat(result.status().getCode(), is(Status.Code.UNIMPLEMENTED));
        assertThat(result.trailers().get(GRPC_ACCEPT_ENCODING), containsString("gzip"));
    }

    private Metadata requestMetadata() {
        Metadata metadata = new Metadata();
        metadata.put(INITIAL_METADATA_KEY, "initial-metadata");
        metadata.put(TRAILING_METADATA_KEY, "ab".getBytes(StandardCharsets.UTF_8));
        return metadata;
    }

    private <ReqT, ResT> CallResult<ResT> unaryCall(MethodDescriptor<ReqT, ResT> method,
                                                    Metadata metadata,
                                                    ReqT request) throws InterruptedException {
        RecordingListener<ResT> listener = new RecordingListener<>();
        ClientCall<ReqT, ResT> call = channel.newCall(method, CallOptions.DEFAULT);
        call.start(listener, metadata);
        call.request(1);
        call.sendMessage(request);
        call.halfClose();
        return listener.await();
    }

    private <ReqT, ResT> CallResult<ResT> streamingCall(MethodDescriptor<ReqT, ResT> method,
                                                        Metadata metadata,
                                                        List<ReqT> requests) throws InterruptedException {
        RecordingListener<ResT> listener = new RecordingListener<>();
        ClientCall<ReqT, ResT> call = channel.newCall(method, CallOptions.DEFAULT);
        call.start(listener, metadata);
        call.request(Integer.MAX_VALUE);
        requests.forEach(call::sendMessage);
        call.halfClose();
        return listener.await();
    }

    private static MethodDescriptor<Strings.StringMessage, Strings.StringMessage> missingUnaryMethod(
            String serviceName,
            String methodName) {
        MethodDescriptor<Strings.StringMessage, Strings.StringMessage> upperMethod = StringServiceGrpc.getUpperMethod();
        return MethodDescriptor.<Strings.StringMessage, Strings.StringMessage>newBuilder()
                .setType(MethodDescriptor.MethodType.UNARY)
                .setFullMethodName(MethodDescriptor.generateFullMethodName(serviceName, methodName))
                .setRequestMarshaller(upperMethod.getRequestMarshaller())
                .setResponseMarshaller(upperMethod.getResponseMarshaller())
                .build();
    }

    private static List<String> texts(List<Strings.StringMessage> messages) {
        return messages.stream()
                .map(Strings.StringMessage::getText)
                .toList();
    }

    private record CallResult<T>(Metadata headers,
                                 List<T> messages,
                                 Status status,
                                 Metadata trailers) {
    }

    private static final class RecordingListener<T> extends ClientCall.Listener<T> {
        private final CountDownLatch completion = new CountDownLatch(1);
        private final List<T> messages = new CopyOnWriteArrayList<>();

        private volatile Metadata headers;
        private volatile Status status;
        private volatile Metadata trailers;

        @Override
        public void onHeaders(Metadata headers) {
            this.headers = headers;
        }

        @Override
        public void onMessage(T message) {
            messages.add(message);
        }

        @Override
        public void onClose(Status status, Metadata trailers) {
            this.status = status;
            this.trailers = trailers;
            completion.countDown();
        }

        private void awaitMessages(int expectedMessages) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
            while (System.nanoTime() < deadline) {
                if (messages.size() >= expectedMessages) {
                    break;
                }
                Thread.sleep(10);
            }
            assertThat(messages.size(), is(expectedMessages));
        }

        private List<T> messages() {
            return List.copyOf(messages);
        }

        private CallResult<T> await() throws InterruptedException {
            assertThat(completion.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), is(true));
            return new CallResult<>(headers, List.copyOf(messages), status, trailers);
        }
    }
}
