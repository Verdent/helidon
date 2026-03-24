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

class GrpcHttpStatusMappingTest {

    @Test
    void testGrpcStatusTakesPrecedenceOverHttpFallback() {
        // Spec note: the official HTTP-to-gRPC fallback table only applies when
        // grpc-status is missing; an explicit grpc-status must win.
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
        // Spec note: the official HTTP-to-gRPC fallback mapping translates HTTP
        // 404 responses without grpc-status into UNIMPLEMENTED.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 404);

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.UNIMPLEMENTED));
        assertThat(status.getDescription(), containsString("404"));
    }

    @Test
    void testMissingGrpcStatusMapsHttp503ToUnavailable() {
        // Spec note: the official HTTP-to-gRPC fallback mapping translates HTTP
        // 503 responses without grpc-status into UNAVAILABLE.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 503);

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.UNAVAILABLE));
        assertThat(status.getDescription(), containsString("503"));
    }

    @Test
    void testNonGrpcContentTypeMapsToUnknown() {
        // Spec note: PROTOCOL-HTTP2 requires clients to synthesize a final
        // status if a response uses a non-gRPC content-type and omits
        // grpc-status, even if the HTTP status is 200.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 200);
        headers.set(HeaderNames.CONTENT_TYPE, "text/plain");

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.UNKNOWN));
        assertThat(status.getDescription(), containsString("invalid content-type"));
    }

    @Test
    void testMissingGrpcStatusOnGrpcContentTypeMapsToUnknown() {
        // Spec note: a response with HTTP 200 and application/grpc is still not
        // complete without grpc-status; the client must not treat it as success.
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(Http2Headers.STATUS_NAME, 200);
        headers.set(HeaderNames.CONTENT_TYPE, "application/grpc+proto");

        Status status = GrpcBaseClientCall.finalStatus(headers);

        assertThat(status.getCode(), is(Status.Code.UNKNOWN));
        assertThat(status.getDescription(), containsString("missing grpc-status"));
    }
}
