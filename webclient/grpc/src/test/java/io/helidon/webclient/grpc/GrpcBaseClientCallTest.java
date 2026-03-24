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
package io.helidon.webclient.grpc;

import java.util.concurrent.TimeUnit;

import io.helidon.grpc.core.GrpcHeadersUtil;
import io.helidon.http.HeaderNames;
import io.helidon.http.WritableHeaders;
import io.helidon.http.http2.Http2Headers;

import io.grpc.CallOptions;
import io.grpc.Metadata;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;

/**
 * Client request header compliance tests based on the gRPC over HTTP/2 wire specification.
 * <p>
 * Official reference:
 * <a href="https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md">gRPC over HTTP/2</a>.
 */
class GrpcBaseClientCallTest {

    @Test
    void testSetupHeadersIncludeGrpcTransportRequirements() {
        // * **Request-Headers** → Call-Definition *Custom-Metadata
        // * **Method** → ":method POST"
        // * **Path** → ":path" "/" Service-Name "/" {_method name_}
        // * **Scheme** → ":scheme " ("http" / "https")
        // * **TE** → "te" "trailers" ; Used to detect incompatible proxies
        // * **Content-Type** → "content-type" "application/grpc" [("+proto" / "+json" / {_custom_})]
        // * **Message-Accept-Encoding** → "grpc-accept-encoding" Content-Coding *(","
        //   Content-Coding)
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        Metadata metadata = new Metadata();
        Metadata.Key<String> key = Metadata.Key.of("cookie", Metadata.ASCII_STRING_MARSHALLER);
        metadata.put(key, "sugar");
        WritableHeaders<?> headers = GrpcBaseClientCall.setupHeaders(metadata, "localhost", "foo");
        assertThat(headers.size(), greaterThan(4));
        assertThat(headers.get(Http2Headers.AUTHORITY_NAME).get(), is("localhost"));
        assertThat(headers.get(Http2Headers.METHOD_NAME).get(), is("POST"));
        assertThat(headers.get(Http2Headers.PATH_NAME).get(), is("/foo"));
        assertThat(headers.get(Http2Headers.SCHEME_NAME).get(), is("http"));
        assertThat(headers.get(HeaderNames.COOKIE).get(), is("sugar"));
        assertThat(headers.get(HeaderNames.CONTENT_TYPE).get(), is("application/grpc"));
        assertThat(headers.get(HeaderNames.TE).get(), is("trailers"));
        assertThat(headers.get(HeaderNames.create("grpc-accept-encoding")).get(), is("gzip"));
    }

    @Test
    void testSetupHeadersIncludeGrpcTimeoutWhenDeadlineIsPresent() {
        // * **Timeout** → "grpc-timeout" TimeoutValue TimeoutUnit
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        WritableHeaders<?> headers = GrpcBaseClientCall.setupHeaders(new Metadata(),
                                                                     "localhost",
                                                                     "foo",
                                                                     CallOptions.DEFAULT.withDeadlineAfter(10,
                                                                                                           TimeUnit.SECONDS));

        assertThat(headers.contains(GrpcBaseClientCall.GRPC_TIMEOUT_NAME), is(true));
        assertThat(GrpcHeadersUtil.decodeTimeout(headers.get(GrpcBaseClientCall.GRPC_TIMEOUT_NAME).get()) > 0, is(true));
    }

    @Test
    void testSetupHeadersUseTheActualRequestScheme() {
        // * **Scheme** → ":scheme " ("http" / "https")
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        WritableHeaders<?> headers = GrpcBaseClientCall.setupHeaders(new Metadata(),
                                                                     "localhost",
                                                                     "foo",
                                                                     CallOptions.DEFAULT,
                                                                     "https");

        assertThat(headers.get(Http2Headers.SCHEME_NAME).get(), is("https"));
    }

    @Test
    void testSetupHeadersIncludeGrpcEncodingWhenCompressionIsConfigured() {
        // * **Message-Encoding** → "grpc-encoding" Content-Coding
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        WritableHeaders<?> headers = GrpcBaseClientCall.setupHeaders(new Metadata(),
                                                                     "localhost",
                                                                     "foo",
                                                                     CallOptions.DEFAULT.withCompression("gzip"));

        assertThat(headers.get(GrpcBaseClientCall.GRPC_ENCODING_NAME).get(), is("gzip"));
    }
}
