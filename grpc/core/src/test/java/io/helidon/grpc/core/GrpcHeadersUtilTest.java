/*
 * Copyright (c) 2025, 2026 Oracle and/or its affiliates.
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
package io.helidon.grpc.core;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.StreamSupport;

import io.helidon.http.HeaderNames;
import io.helidon.http.WritableHeaders;
import io.helidon.http.http2.Http2Headers;

import io.grpc.Metadata;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GrpcHeadersUtilTest {

    @Test
    void testAsciiMetadataPreservesRepeatedValues() {
        // Spec note: metadata maps to HTTP/2 headers and repeated ASCII metadata
        // values must survive the header conversion without being collapsed.
        Metadata metadata = new Metadata();
        Metadata.Key<String> key = Metadata.Key.of("cookie", Metadata.ASCII_STRING_MARSHALLER);
        metadata.put(key, "sugar");
        metadata.put(key, "almond");
        WritableHeaders<?> headers = WritableHeaders.create();
        GrpcHeadersUtil.updateHeaders(headers, metadata);
        // there is exactly one header name: `Cookie`
        assertThat(headers.size(), is(1));
        List<String> values = headers.get(HeaderNames.COOKIE).allValues();
        assertThat(values, hasItem("sugar"));
        assertThat(values, hasItem("almond"));
    }

    @Test
    void testBinaryMetadataUsesBase64HeaderEncoding() {
        // Spec note: PROTOCOL-HTTP2 requires "-bin" metadata values to be sent
        // using Base64 over HTTP/2 headers.
        Metadata metadata = new Metadata();
        Metadata.Key<byte[]> key = Metadata.Key.of("secret-bin", Metadata.BINARY_BYTE_MARSHALLER);
        byte[] mySecret = "my-secret".getBytes(StandardCharsets.UTF_8);
        metadata.put(key, mySecret);
        WritableHeaders<?> headers = WritableHeaders.create();
        GrpcHeadersUtil.updateHeaders(headers, metadata);
        assertThat(headers.size(), is(1));
        List<String> values = headers.get(HeaderNames.create("secret-bin")).allValues();
        byte[] value = Base64.getDecoder().decode(values.getFirst().getBytes(StandardCharsets.UTF_8));
        assertThat(new String(value, StandardCharsets.UTF_8), is("my-secret"));
    }

    @Test
    void testBinaryMetadataUsesUnpaddedBase64Encoding() {
        // Spec note: PROTOCOL-HTTP2 allows implementations to emit unpadded
        // Base64 for binary metadata values.
        Metadata metadata = new Metadata();
        Metadata.Key<byte[]> key = Metadata.Key.of("secret-bin", Metadata.BINARY_BYTE_MARSHALLER);
        metadata.put(key, new byte[] {'a'});

        WritableHeaders<?> headers = WritableHeaders.create();
        GrpcHeadersUtil.updateHeaders(headers, metadata);

        List<String> values = headers.get(HeaderNames.create("secret-bin")).allValues();
        assertThat(values, contains("YQ"));
    }

    @Test
    void testAsciiHeadersRoundTripBackToMetadata() {
        // Spec note: ASCII metadata round-trips through HTTP/2 headers, including
        // repeated values with the same header name.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(HeaderNames.COOKIE, "sugar", "almond");
        Http2Headers http2Headers = mock(Http2Headers.class);
        when(http2Headers.httpHeaders()).thenReturn(headers);
        Metadata metadata = GrpcHeadersUtil.toMetadata(http2Headers);
        Metadata.Key<String> key = Metadata.Key.of("cookie", Metadata.ASCII_STRING_MARSHALLER);
        assertThat(metadata.containsKey(key), is(true));
        Set<String> values = new HashSet<>();
        metadata.getAll(key).forEach(values::add);
        assertThat(values, hasItem("sugar"));
        assertThat(values, hasItem("almond"));
    }

    @Test
    void testCommaJoinedBinaryHeadersSplitBackIntoMetadataEntries() {
        // Spec note: PROTOCOL-HTTP2 requires receivers to accept comma-joined
        // binary header values and split them into separate metadata entries.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(HeaderNames.create("secret-bin"), "YQ,Yg");

        Metadata metadata = GrpcHeadersUtil.toMetadata(headers);
        Metadata.Key<byte[]> key = Metadata.Key.of("secret-bin", Metadata.BINARY_BYTE_MARSHALLER);

        List<byte[]> values = StreamSupport.stream(metadata.getAll(key).spliterator(), false).toList();
        assertThat(values.size(), is(2));
        assertThat(new String(values.get(0), StandardCharsets.UTF_8), is("a"));
        assertThat(new String(values.get(1), StandardCharsets.UTF_8), is("b"));
    }

    @Test
    void testPaddedBinaryHeadersAreAccepted() {
        // Spec note: PROTOCOL-HTTP2 requires binary metadata decoders to accept
        // padded and unpadded Base64 representations.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(HeaderNames.create("secret-bin"), "YQ==");

        Metadata metadata = GrpcHeadersUtil.toMetadata(headers);
        Metadata.Key<byte[]> key = Metadata.Key.of("secret-bin", Metadata.BINARY_BYTE_MARSHALLER);

        assertThat(new String(metadata.get(key), StandardCharsets.UTF_8), is("a"));
    }

    @Test
    void testGrpcStatusMessagePercentEncodingRoundTrip() {
        // Spec note: grpc-message header values use percent-encoding for bytes
        // outside the visible ASCII range and must round-trip losslessly.
        String message = "A special message % \n and unicode \u00A9";

        String encoded = GrpcHeadersUtil.encodeMessage(message);

        assertThat(encoded.contains("%"), is(true));
        assertThat(GrpcHeadersUtil.decodeMessage(encoded), is(message));
    }

    @Test
    void testGrpcStatusMessageInvalidPercentEscapesArePreserved() {
        // Spec note: invalid percent-escape sequences in grpc-message must not
        // corrupt the value; undecodable escapes should be preserved as-is.
        String encoded = "Bad%2 escape%ZZ";

        assertThat(GrpcHeadersUtil.decodeMessage(encoded), is(encoded));
    }
}
