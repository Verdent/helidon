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
import java.util.concurrent.TimeUnit;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Wire-format compliance tests for gRPC metadata, status-message, and timeout handling.
 * <p>
 * Official reference:
 * <a href="https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md">gRPC over HTTP/2</a>.
 */
class GrpcHeadersUtilTest {

    @Test
    void testAsciiMetadataPreservesRepeatedValues() {
        // **Custom-Metadata** header order is not guaranteed to be preserved except for values with
        // duplicate header names.
        // Duplicate header names may have their values joined with "," as the delimiter and be
        // considered semantically equivalent.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
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
        // Note that HTTP2 does not allow arbitrary octet sequences for header values so binary
        // header values must be encoded using Base64 as per
        // https://tools.ietf.org/html/rfc4648#section-4.
        // Implementations MUST accept padded and un-padded values and should emit un-padded values.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
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
        // Note that HTTP2 does not allow arbitrary octet sequences for header values so binary
        // header values must be encoded using Base64 as per
        // https://tools.ietf.org/html/rfc4648#section-4.
        // Implementations MUST accept padded and un-padded values and should emit un-padded values.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
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
        // **Custom-Metadata** header order is not guaranteed to be preserved except for values with
        // duplicate header names.
        // Duplicate header names may have their values joined with "," as the delimiter and be
        // considered semantically equivalent.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
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
        // Implementations must split **Binary-Header**s on "," before decoding the
        // Base64-encoded values.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
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
        // Note that HTTP2 does not allow arbitrary octet sequences for header values so binary
        // header values must be encoded using Base64 as per
        // https://tools.ietf.org/html/rfc4648#section-4.
        // Implementations MUST accept padded and un-padded values and should emit un-padded values.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.add(HeaderNames.create("secret-bin"), "YQ==");

        Metadata metadata = GrpcHeadersUtil.toMetadata(headers);
        Metadata.Key<byte[]> key = Metadata.Key.of("secret-bin", Metadata.BINARY_BYTE_MARSHALLER);

        assertThat(new String(metadata.get(key), StandardCharsets.UTF_8), is("a"));
    }

    @Test
    void testGrpcStatusMessagePercentEncodingRoundTrip() {
        // The value portion of **Status-Message** is conceptually a Unicode string description of
        // the error, physically encoded as UTF-8 followed by percent-encoding.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#responses
        String message = "A special message % \n and unicode \u00A9";

        String encoded = GrpcHeadersUtil.encodeMessage(message);

        assertThat(encoded.contains("%"), is(true));
        assertThat(GrpcHeadersUtil.decodeMessage(encoded), is(message));
    }

    @Test
    void testGrpcStatusMessageInvalidPercentEscapesArePreserved() {
        // When decoding invalid values, implementations MUST NOT error or throw away the message.
        // At worst, the implementation can abort decoding the status message altogether such that
        // the user would received the raw percent-encoded form.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#responses
        String encoded = "Bad%2 escape%ZZ";

        assertThat(GrpcHeadersUtil.decodeMessage(encoded), is(encoded));
    }

    @Test
    void testGrpcTimeoutEncodesUsingTheSmallestFittingUnit() {
        // Paraphrase: grpc-timeout is a positive ASCII integer with at most 8 digits plus a unit
        // suffix, so the encoder must choose a unit that keeps the serialized timeout within that
        // grammar.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        long timeoutNanos = TimeUnit.MILLISECONDS.toNanos(100);

        assertThat(GrpcHeadersUtil.encodeTimeout(timeoutNanos), is("100000u"));
    }

    @Test
    void testGrpcTimeoutEncoderEmitsPositiveImmediateDeadlines() {
        // Paraphrase: grpc-timeout still has to serialize as a positive TimeoutValue plus
        // TimeoutUnit, so an immediate deadline cannot be encoded as zero.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        assertThat(GrpcHeadersUtil.encodeTimeout(0), is("1n"));
    }

    @Test
    void testGrpcTimeoutParsesBackToNanoseconds() {
        // * **Timeout** → "grpc-timeout" TimeoutValue TimeoutUnit
        // * **TimeoutUnit** → Hour / Minute / Second / Millisecond / Microsecond / Nanosecond
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        assertThat(GrpcHeadersUtil.decodeTimeout("42S"), is(TimeUnit.SECONDS.toNanos(42)));
    }

    @Test
    void testGrpcTimeoutRejectsValuesLongerThanEightDigits() {
        // * **TimeoutValue** → {_positive integer as ASCII string of at most 8 digits_}
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> GrpcHeadersUtil.decodeTimeout("123456789n"));

        assertThat(exception.getMessage(), is("bad timeout format"));
    }
}
