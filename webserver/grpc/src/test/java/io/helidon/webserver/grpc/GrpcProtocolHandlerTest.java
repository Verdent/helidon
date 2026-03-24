/*
 * Copyright (c) 2024, 2026 Oracle and/or its affiliates.
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

package io.helidon.webserver.grpc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import io.helidon.common.buffers.BufferData;
import io.helidon.common.buffers.DataReader;
import io.helidon.common.buffers.DataWriter;
import io.helidon.common.socket.PeerInfo;
import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.WritableHeaders;
import io.helidon.http.http2.Http2Headers;
import io.helidon.http.http2.Http2StreamState;

import io.helidon.webserver.ConnectionContext;
import io.helidon.webserver.ListenerContext;
import io.helidon.webserver.Router;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import io.grpc.Status;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class GrpcProtocolHandlerTest {

    private static final HeaderName GRPC_ACCEPT_ENCODING = HeaderNames.create("grpc-accept-encoding");
    private static final HeaderName GRPC_ENCODING = HeaderNames.create("grpc-encoding");
    private static final Metadata.Key<String> GRPC_ACCEPT_ENCODING_KEY =
            Metadata.Key.of("grpc-accept-encoding", Metadata.ASCII_STRING_MARSHALLER);

    @Test
    void testIdentityAcceptEncodingKeepsIdentityCompression() {
        // Spec note: PROTOCOL-HTTP2 defines identity as the implicit "no
        // compression" encoding, so advertising only identity must keep the
        // response stream uncompressed.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(GRPC_ACCEPT_ENCODING, "identity");
        GrpcProtocolHandler<Object, Object> handler = newHandler(headers, GrpcConfig.create());

        handler.initCompression(null, headers);

        assertThat(handler.identityCompressor(), is(true));
    }

    @Test
    void testGzipAcceptEncodingNegotiatesGzipCompression() {
        // Spec note: when the client advertises gzip in grpc-accept-encoding,
        // the server may select gzip for its responses.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(GRPC_ACCEPT_ENCODING, "gzip");
        GrpcProtocolHandler<Object, Object> handler = newHandler(headers, GrpcConfig.create());

        handler.initCompression(null, headers);

        assertThat(handler.identityCompressor(), is(false));
    }

    @Test
    void testCommaJoinedAcceptEncodingNegotiatesGzipCompression() {
        // Spec note: HTTP/2 allows repeated header values to be comma-joined,
        // so grpc-accept-encoding must still parse beyond the first token in a
        // single comma-separated header value to reach a later supported codec.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(GRPC_ACCEPT_ENCODING, "snappy, gzip");
        GrpcProtocolHandler<Object, Object> handler = newHandler(headers, GrpcConfig.create());

        handler.initCompression(null, headers);

        assertThat(handler.identityCompressor(), is(false));
    }

    @Test
    void testCompressionDisabledIgnoresGzipNegotiation() {
        // Spec note: disabling server-side compression must override any
        // grpc-accept-encoding negotiation and keep the response identity.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(GRPC_ACCEPT_ENCODING, "gzip");
        GrpcProtocolHandler<Object, Object> handler = newHandler(headers,
                                                                 GrpcConfig.builder()
                                                                         .enableCompression(false)
                                                                         .build());

        handler.initCompression(null, headers);

        assertThat(handler.identityCompressor(), is(true));
    }

    @Test
    void testUnsupportedRequestCompressionClosesWithUnimplemented() {
        // Spec note: PROTOCOL-HTTP2 requires unsupported grpc-encoding values
        // to fail with UNIMPLEMENTED and advertise the encodings the server
        // does support.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(GRPC_ENCODING, "snappy");
        GrpcProtocolHandler<Object, Object> handler = newHandler(headers, GrpcConfig.create());
        CapturingServerCall serverCall = new CapturingServerCall();

        handler.initCompression(serverCall, headers);

        assertThat(serverCall.status.getCode(), is(Status.Code.UNIMPLEMENTED));
        assertThat(serverCall.trailers.get(GRPC_ACCEPT_ENCODING_KEY), containsString("gzip"));
        assertThat(handler.streamState(), is(Http2StreamState.CLOSED));
    }

    @Test
    void testCompressedRequestStreamSignalsEofAtMessageBoundary() throws IOException {
        // Spec note: upstream interop case "client_compressed_unary" depends on
        // the compressed request body being exposed as a bounded gzip stream
        // that reaches EOF exactly at the gRPC message boundary.
        byte[] compressed = gzip("hello grpc");

        try (GZIPInputStream gzipInputStream = new GZIPInputStream(new GrpcProtocolHandler.BufferDataInputStream(
                BufferData.createReadOnly(compressed, 0, compressed.length)))) {
            byte[] decompressed = gzipInputStream.readAllBytes();

            assertThat(new String(decompressed, StandardCharsets.UTF_8), is("hello grpc"));
        }
    }

    @Test
    void testHalfClosedLocalThenRemoteTransitionsToClosed() {
        // Spec note: gRPC rides on HTTP/2 stream states, so once both halves of
        // the stream are closed the transport state must become CLOSED.
        Http2StreamState next = GrpcProtocolHandler.nextStreamState(
                Http2StreamState.HALF_CLOSED_LOCAL, Http2StreamState.HALF_CLOSED_REMOTE);

        assertThat(next, is(Http2StreamState.CLOSED));
    }

    @Test
    void testHalfClosedRemoteThenLocalTransitionsToClosed() {
        // Spec note: gRPC over HTTP/2 must converge to CLOSED regardless of the
        // order in which the local and remote halves close.
        Http2StreamState next = GrpcProtocolHandler.nextStreamState(
                Http2StreamState.HALF_CLOSED_REMOTE, Http2StreamState.HALF_CLOSED_LOCAL);

        assertThat(next, is(Http2StreamState.CLOSED));
    }

    private static GrpcProtocolHandler<Object, Object> newHandler(WritableHeaders<?> headers, GrpcConfig config) {
        return new GrpcProtocolHandler<>(new UnimplementedGrpcConnectionContext(),
                                         Http2Headers.create(headers),
                                         null,
                                         1,
                                         null,
                                         Http2StreamState.OPEN,
                                         null,
                                         config);
    }

    private static byte[] gzip(String text) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(baos)) {
            gzipOutputStream.write(text.getBytes(StandardCharsets.UTF_8));
        }
        return baos.toByteArray();
    }

    private static final class CapturingServerCall extends ServerCall<Object, Object> {
        private Status status;
        private Metadata trailers;

        @Override
        public void request(int numMessages) {
        }

        @Override
        public void sendHeaders(Metadata headers) {
        }

        @Override
        public void sendMessage(Object message) {
        }

        @Override
        public void close(Status status, Metadata trailers) {
            this.status = status;
            this.trailers = trailers;
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public MethodDescriptor<Object, Object> getMethodDescriptor() {
            return null;
        }
    }

    private static class UnimplementedGrpcConnectionContext implements ConnectionContext {
        @Override
        public ListenerContext listenerContext() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override
        public ExecutorService executor() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override
        public DataWriter dataWriter() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override
        public DataReader dataReader() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override
        public Router router() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override
        public PeerInfo remotePeer() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override
        public PeerInfo localPeer() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override
        public boolean isSecure() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override
        public String socketId() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override
        public String childSocketId() {
            throw new UnsupportedOperationException("Should not be called");
        }
    }
}
