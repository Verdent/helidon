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

/**
 * End-to-end interoperability checks for the Helidon gRPC client.
 * <p>
 * Official references:
 * <a href="https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md">gRPC interoperability test descriptions</a>,
 * <a href="https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md">gRPC over HTTP/2</a>.
 */
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
        // This test verifies that custom metadata in either binary or ascii format can be sent as
        // initial-metadata by the client and as both initial- and trailing-metadata by the server.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#custom_metadata
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
        // This test verifies that custom metadata in either binary or ascii format can be sent as
        // initial-metadata by the client and as both initial- and trailing-metadata by the server.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#custom_metadata
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
        // This test verifies that implementations support zero-size messages.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#empty_unary
        CallResult<Strings.StringMessage> result = unaryCall(StringServiceGrpc.getUpperMethod(),
                                                             new Metadata(),
                                                             Strings.StringMessage.getDefaultInstance());

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().getFirst().getText(), is(""));
    }

    @Test
    void testLargeUnaryPayloadSpanningMultipleHttp2Frames() throws InterruptedException {
        // This test verifies unary calls succeed in sending messages, and touches on flow control
        // (even if compression is enabled on the channel).
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#large_unary
        String requestText = "grpc".repeat(32 * 1024);

        CallResult<Strings.StringMessage> result = unaryCall(StringServiceGrpc.getUpperMethod(),
                                                             new Metadata(),
                                                             newStringMessage(requestText));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().getFirst().getText(), is(requestText.toUpperCase(Locale.ROOT)));
    }

    @Test
    void testServerStreamingRoundTrip() throws InterruptedException {
        // This test verifies that server-only streaming succeeds.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#server_streaming
        CallResult<Strings.StringMessage> result = streamingCall(StringServiceGrpc.getSplitMethod(),
                                                                 new Metadata(),
                                                                 List.of(newStringMessage("one two three")));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(texts(result.messages()), contains("one", "two", "three"));
    }

    @Test
    void testClientStreamingRoundTrip() throws InterruptedException {
        // This test verifies that client-only streaming succeeds.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#client_streaming
        CallResult<Strings.StringMessage> result = streamingCall(StringServiceGrpc.getJoinMethod(),
                                                                 new Metadata(),
                                                                 List.of(newStringMessage("one"),
                                                                         newStringMessage("two"),
                                                                         newStringMessage("three")));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().getFirst().getText(), is("one two three"));
    }

    @Test
    void testEmptyBidirectionalStreamCompletesWithoutMessages() throws InterruptedException {
        // This test verifies that streams support having zero-messages in both directions.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#empty_stream
        CallResult<Strings.StringMessage> result = streamingCall(StringServiceGrpc.getEchoMethod(),
                                                                 new Metadata(),
                                                                 List.of());

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.messages().isEmpty(), is(true));
    }

    @Test
    void testDeadlineIsSentAsGrpcTimeoutHeader() {
        // This test verifies that an RPC request whose lifetime exceeds its configured timeout
        // value will end with the DeadlineExceeded status.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#timeout_on_sleeping_server
        LAST_REQUEST_DEADLINE_MILLIS.set(null);
        StringServiceGrpc.StringServiceBlockingStub service = StringServiceGrpc.newBlockingStub(channel)
                .withDeadlineAfter(100, TimeUnit.MILLISECONDS);

        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class,
                                                        () -> service.upper(newStringMessage(SLEEP_PREFIX + "250")));

        assertThat(exception.getStatus().getCode(), is(Status.Code.DEADLINE_EXCEEDED));
        assertThat(LAST_REQUEST_DEADLINE_MILLIS.get() != null && LAST_REQUEST_DEADLINE_MILLIS.get() > 0, is(true));
    }

    @Test
    void testUnaryStatusCodeAndMessage() {
        // This test verifies unary calls succeed in sending messages, and propagate back status
        // code and message sent along with the messages.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#status_code_and_message
        StringServiceGrpc.StringServiceBlockingStub service = StringServiceGrpc.newBlockingStub(channel);

        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class,
                                                        () -> service.badMethod(newStringMessage("bad request")));

        assertThat(exception.getStatus().getCode(), is(Status.Code.INVALID_ARGUMENT));
        assertThat(exception.getStatus().getDescription(), is("bad request"));
    }

    @Test
    void testSpecialStatusMessageRoundTrip() {
        // This test verifies Unicode and whitespace is correctly processed in status message.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#special_status_message
        StringServiceGrpc.StringServiceBlockingStub service = StringServiceGrpc.newBlockingStub(channel);
        String statusMessage = "Bad input % \n and unicode \u00A9";

        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class,
                                                        () -> service.badMethod(newStringMessage(statusMessage)));

        assertThat(exception.getStatus().getCode(), is(Status.Code.INVALID_ARGUMENT));
        assertThat(exception.getStatus().getDescription(), is(statusMessage));
    }

    @Test
    void testBidirectionalStatusCodeAndMessage() throws InterruptedException {
        // received status code is the same as the sent code for both Procedure steps 1 and 2
        // received status message is the same as the sent message for both Procedure steps 1 and 2
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#status_code_and_message
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
        // This test verifies that full duplex bidi is supported.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#ping_pong
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
    void testCancelAfterBeginClosesWithCancelled() throws InterruptedException {
        // This test verifies that a request can be cancelled after metadata has been sent but
        // before payloads are sent.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#cancel_after_begin
        RecordingListener<Strings.StringMessage> listener = new RecordingListener<>();
        ClientCall<Strings.StringMessage, Strings.StringMessage> call =
                channel.newCall(StringServiceGrpc.getJoinMethod(), CallOptions.DEFAULT);

        call.start(listener, new Metadata());
        call.request(1);
        call.cancel("cancel_after_begin", null);

        CallResult<Strings.StringMessage> result = listener.await();
        assertThat(result.status().getCode(), is(Status.Code.CANCELLED));
    }

    @Test
    void testCancelAfterFirstResponseClosesWithCancelled() throws InterruptedException {
        // This test verifies that a request can be cancelled after receiving a message from the
        // server.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#cancel_after_first_response
        RecordingListener<Strings.StringMessage> listener = new RecordingListener<>();
        ClientCall<Strings.StringMessage, Strings.StringMessage> call =
                channel.newCall(StringServiceGrpc.getEchoMethod(), CallOptions.DEFAULT);

        call.start(listener, new Metadata());
        call.request(1);
        call.sendMessage(newStringMessage("one"));
        listener.awaitMessages(1);
        call.cancel("cancel_after_first_response", null);

        CallResult<Strings.StringMessage> result = listener.await();
        assertThat(texts(result.messages()), contains("one"));
        assertThat(result.status().getCode(), is(Status.Code.CANCELLED));
    }

    @Test
    void testMissingMethodReturnsUnimplemented() throws InterruptedException {
        // This test verifies that calling an unimplemented RPC method returns the UNIMPLEMENTED
        // status code.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#unimplemented_method
        CallResult<Strings.StringMessage> result = unaryCall(missingUnaryMethod("StringService", "MissingMethod"),
                                                             new Metadata(),
                                                             newStringMessage("hello"));

        assertThat(result.status().getCode(), is(Status.Code.UNIMPLEMENTED));
        assertThat(result.headers(), nullValue());
    }

    @Test
    void testMissingServiceReturnsUnimplemented() throws InterruptedException {
        // This test verifies calling an unimplemented server returns the UNIMPLEMENTED status code.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#unimplemented_service
        CallResult<Strings.StringMessage> result = unaryCall(missingUnaryMethod("MissingService", "Upper"),
                                                             new Metadata(),
                                                             newStringMessage("hello"));

        assertThat(result.status().getCode(), is(Status.Code.UNIMPLEMENTED));
        assertThat(result.headers(), nullValue());
    }

    @Test
    void testCompressedResponseRoundTrip() throws InterruptedException {
        // This test verifies the server can compress unary messages.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#server_compressed_unary
        CallResult<Strings.StringMessage> result = unaryCall(StringServiceGrpc.getUpperMethod(),
                                                             new Metadata(),
                                                             newStringMessage("hello"));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.headers().get(GRPC_ENCODING), is("gzip"));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().getFirst().getText(), is("HELLO"));
    }

    @Test
    void testCompressedServerStreamingRoundTrip() throws InterruptedException {
        // Paraphrase: this covers the compressed-response portion of
        // server_compressed_streaming.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#server_compressed_streaming
        CallResult<Strings.StringMessage> result = streamingCall(StringServiceGrpc.getSplitMethod(),
                                                                 new Metadata(),
                                                                 List.of(newStringMessage("one two three")));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.headers().get(GRPC_ENCODING), is("gzip"));
        assertThat(texts(result.messages()), contains("one", "two", "three"));
    }

    @Test
    void testCompressedUnaryRequestRoundTrip() throws InterruptedException {
        // Paraphrase: this covers the compressed unary request path from client_compressed_unary.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#client_compressed_unary
        LAST_REQUEST_ENCODING.set(null);

        CallResult<Strings.StringMessage> result = unaryCall(StringServiceGrpc.getUpperMethod(),
                                                             CallOptions.DEFAULT.withCompression("gzip"),
                                                             new Metadata(),
                                                             newStringMessage("hello"));

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().getFirst().getText(), is("HELLO"));
        assertThat(LAST_REQUEST_ENCODING.get(), containsString("gzip"));
    }

    @Test
    void testCompressedClientStreamingRoundTrip() throws InterruptedException {
        // Paraphrase: this covers the successful mixed compressed and uncompressed request path from
        // client_compressed_streaming.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/interop-test-descriptions.md#client_compressed_streaming
        LAST_REQUEST_ENCODING.set(null);
        RecordingListener<Strings.StringMessage> listener = new RecordingListener<>();
        ClientCall<Strings.StringMessage, Strings.StringMessage> call =
                channel.newCall(StringServiceGrpc.getJoinMethod(), CallOptions.DEFAULT.withCompression("gzip"));

        call.start(listener, new Metadata());
        call.request(1);
        call.setMessageCompression(true);
        call.sendMessage(newStringMessage("one"));
        call.setMessageCompression(false);
        call.sendMessage(newStringMessage("two"));
        call.halfClose();

        CallResult<Strings.StringMessage> result = listener.await();

        assertThat(result.status().getCode(), is(Status.Code.OK));
        assertThat(result.messages().size(), is(1));
        assertThat(result.messages().getFirst().getText(), is("one two"));
        assertThat(LAST_REQUEST_ENCODING.get(), containsString("gzip"));
    }

    @Test
    void testUnsupportedCompressionAdvertisesSupportedEncodings() throws InterruptedException {
        // If a client message is compressed by an algorithm that is not supported by a server, the
        // message WILL result in an `UNIMPLEMENTED` error status on the server.
        // The server will then include a `grpc-accept-encoding` response header which specifies the
        // algorithms that the server accepts.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/compression.md#compression-method-asymmetry-between-peers
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
        return unaryCall(method, CallOptions.DEFAULT, metadata, request);
    }

    private <ReqT, ResT> CallResult<ResT> unaryCall(MethodDescriptor<ReqT, ResT> method,
                                                    CallOptions callOptions,
                                                    Metadata metadata,
                                                    ReqT request) throws InterruptedException {
        RecordingListener<ResT> listener = new RecordingListener<>();
        ClientCall<ReqT, ResT> call = channel.newCall(method, callOptions);
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
