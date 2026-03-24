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
        // * **Message-Accept-Encoding** → "grpc-accept-encoding" Content-Coding *(","
        //   Content-Coding)
        // For every message a server is requested to compress using an algorithm it knows the
        // client doesn't support (as indicated by the last `grpc-accept-encoding` header received
        // from the client), it SHALL send the message uncompressed.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        // Spec: https://github.com/grpc/grpc/blob/master/doc/compression.md#compression-method-asymmetry-between-peers
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(GRPC_ACCEPT_ENCODING, "identity");
        GrpcProtocolHandler<Object, Object> handler = newHandler(headers, GrpcConfig.create());

        handler.initCompression(null, headers);

        assertThat(handler.identityCompressor(), is(true));
    }

    @Test
    void testGzipAcceptEncodingNegotiatesGzipCompression() {
        // * **Message-Accept-Encoding** → "grpc-accept-encoding" Content-Coding *(","
        //   Content-Coding)
        // A server is always aware of what its clients support, as clients disclose it in the
        // Message-Accept-Encoding header as part of the RPC.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        // Spec: https://github.com/grpc/grpc/blob/master/doc/compression.md#compression-levels-and-algorithms
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(GRPC_ACCEPT_ENCODING, "gzip");
        GrpcProtocolHandler<Object, Object> handler = newHandler(headers, GrpcConfig.create());

        handler.initCompression(null, headers);

        assertThat(handler.identityCompressor(), is(false));
    }

    @Test
    void testCommaJoinedAcceptEncodingNegotiatesGzipCompression() {
        // * **Message-Accept-Encoding** → "grpc-accept-encoding" Content-Coding *(","
        //   Content-Coding)
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(GRPC_ACCEPT_ENCODING, "snappy, gzip");
        GrpcProtocolHandler<Object, Object> handler = newHandler(headers, GrpcConfig.create());

        handler.initCompression(null, headers);

        assertThat(handler.identityCompressor(), is(false));
    }

    @Test
    void testCompressionDisabledIgnoresGzipNegotiation() {
        // If the user (through the previously described mechanisms) requests to disable compression
        // the next message MUST be sent uncompressed.
        // This applies to both the unary and streaming cases.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/compression.md#specific-disabling-of-compression
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
        // If a client message is compressed by an algorithm that is not supported by a server, the
        // message WILL result in an `UNIMPLEMENTED` error status on the server.
        // The server will then include a `grpc-accept-encoding` response header which specifies the
        // algorithms that the server accepts.
        // The returned `grpc-accept-encoding` header MUST NOT contain the compression method
        // (encoding) used.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/compression.md#compression-method-asymmetry-between-peers
        // Spec: https://github.com/grpc/grpc/blob/master/doc/compression.md#test-cases
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
        // A **Compressed-Flag** value of 1 indicates that the binary octet sequence of **Message**
        // is compressed using the mechanism declared by the **Message-Encoding** header.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        byte[] compressed = gzip("hello grpc");

        try (GZIPInputStream gzipInputStream = new GZIPInputStream(new GrpcProtocolHandler.BufferDataInputStream(
                BufferData.createReadOnly(compressed, 0, compressed.length)))) {
            byte[] decompressed = gzipInputStream.readAllBytes();

            assertThat(new String(decompressed, StandardCharsets.UTF_8), is("hello grpc"));
        }
    }

    @Test
    void testHalfClosedLocalThenRemoteTransitionsToClosed() {
        // Paraphrase: the gRPC transport mapping uses the HTTP/2 stream lifecycle for RPC closure,
        // so opposite half-closed states must collapse to a fully closed stream.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#http2-transport-mapping
        Http2StreamState next = GrpcProtocolHandler.nextStreamState(
                Http2StreamState.HALF_CLOSED_LOCAL, Http2StreamState.HALF_CLOSED_REMOTE);

        assertThat(next, is(Http2StreamState.CLOSED));
    }

    @Test
    void testHalfClosedRemoteThenLocalTransitionsToClosed() {
        // Paraphrase: the gRPC transport mapping uses the HTTP/2 stream lifecycle for RPC closure,
        // so opposite half-closed states must collapse to a fully closed stream.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#http2-transport-mapping
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
