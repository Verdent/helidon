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
package io.helidon.webclient.grpc;

import io.helidon.http.HeaderNames;
import io.helidon.http.WritableHeaders;
import io.helidon.http.http2.Http2Headers;

import io.grpc.Status;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Client fallback status mapping tests for non-conforming HTTP responses.
 * <p>
 * Official references:
 * <a href="https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md">HTTP to gRPC status mapping</a>,
 * <a href="https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md">gRPC over HTTP/2</a>.
 */
class GrpcHttpStatusMappingTest {

    @Test
    void testGrpcStatusTakesPrecedenceOverHttpFallback() {
        // If grpc-status was provided, it _must_ be used.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md#http-to-grpc-status-code-mapping
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 503);
        headers.set(HeaderNames.CONTENT_TYPE, "application/grpc");
        headers.set(GrpcBaseClientCall.STATUS_NAME, Status.Code.INVALID_ARGUMENT.value());
        headers.set(GrpcBaseClientCall.MESSAGE_NAME, "bad request");

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.INVALID_ARGUMENT));
        assertThat(status.getDescription(), is("bad request"));
    }

    @Test
    void testMissingGrpcStatusMapsHttp404ToUnimplemented() {
        // | 404 Not Found | UNIMPLEMENTED |
        // Spec: https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md#http-to-grpc-status-code-mapping
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 404);

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.UNIMPLEMENTED));
        assertThat(status.getDescription(), containsString("404"));
    }

    @Test
    void testMissingGrpcStatusMapsHttp503ToUnavailable() {
        // | 503 Service Unavailable | UNAVAILABLE |
        // Spec: https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md#http-to-grpc-status-code-mapping
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 503);

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.UNAVAILABLE));
        assertThat(status.getDescription(), containsString("503"));
    }

    @Test
    void testMissingGrpcStatusMapsHttp400ToInternal() {
        // | 400 Bad Request | INTERNAL |
        // Spec: https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md#http-to-grpc-status-code-mapping
        assertFallbackStatus(400, Status.Code.INTERNAL);
    }

    @Test
    void testMissingGrpcStatusMapsAuthFailuresToGrpcStatuses() {
        // | 401 Unauthorized | UNAUTHENTICATED |
        // | 403 Forbidden | PERMISSION_DENIED |
        // Spec: https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md#http-to-grpc-status-code-mapping
        assertFallbackStatus(401, Status.Code.UNAUTHENTICATED);
        assertFallbackStatus(403, Status.Code.PERMISSION_DENIED);
    }

    @Test
    void testMissingGrpcStatusMapsRetryableHttpStatusesToUnavailable() {
        // | 429 Too Many Requests | UNAVAILABLE |
        // | 502 Bad Gateway | UNAVAILABLE |
        // | 504 Gateway Timeout | UNAVAILABLE |
        // Spec: https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md#http-to-grpc-status-code-mapping
        assertFallbackStatus(429, Status.Code.UNAVAILABLE);
        assertFallbackStatus(502, Status.Code.UNAVAILABLE);
        assertFallbackStatus(504, Status.Code.UNAVAILABLE);
    }

    @Test
    void testNonGrpcContentTypeMapsToUnknown() {
        // Implementations should expect broken deployments to send non-200 HTTP status codes in
        // responses as well as a variety of non-GRPC content-types and to omit **Status** &
        // **Status-Message**.
        // Implementations must synthesize a **Status** & **Status-Message** to propagate to the
        // application layer when this occurs.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#responses
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 200);
        headers.set(HeaderNames.CONTENT_TYPE, "text/plain");

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.UNKNOWN));
        assertThat(status.getDescription(), containsString("invalid content-type"));
    }

    @Test
    void testMissingGrpcStatusOnGrpcContentTypeMapsToUnknown() {
        // Status must be sent in **Trailers** even if the status code is OK.
        // Implementations must synthesize a **Status** & **Status-Message** to propagate to the
        // application layer when this occurs.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#responses
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 200);
        headers.set(HeaderNames.CONTENT_TYPE, "application/grpc+proto");

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.UNKNOWN));
        assertThat(status.getDescription(), containsString("missing grpc-status"));
    }

    @Test
    void testGrpcWebContentTypeIsRejectedAsNonGrpc() {
        // * **Content-Type** → "content-type" "application/grpc" [("+proto" / "+json" / {_custom_})]
        // Implementations should expect broken deployments to send non-200 HTTP status codes in
        // responses as well as a variety of non-GRPC content-types and to omit **Status** &
        // **Status-Message**.
        // Implementations must synthesize a **Status** & **Status-Message** to propagate to the
        // application layer when this occurs.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#responses
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 200);
        headers.set(HeaderNames.CONTENT_TYPE, "application/grpc-web");

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.UNKNOWN));
        assertThat(status.getDescription(), containsString("invalid content-type"));
    }

    private static void assertFallbackStatus(int httpStatus, Status.Code expectedCode) {
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, httpStatus);

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(expectedCode));
        assertThat(status.getDescription(), containsString(Integer.toString(httpStatus)));
    }
}
