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

package io.helidon.webserver.grpc;

import io.helidon.http.HeaderNames;
import io.helidon.http.HttpPrologue;
import io.helidon.http.Method;
import io.helidon.http.WritableHeaders;
import io.helidon.http.http2.Http2Headers;
import io.helidon.http.http2.Http2StreamState;
import io.helidon.webserver.Router;
import io.helidon.webserver.http2.spi.SubProtocolResult;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class GrpcProtocolSelectorTest {

    @Test
    void testGrpcWebContentTypeIsNotSelected() {
        // * **Content-Type** → "content-type" "application/grpc" [("+proto" / "+json" / {_custom_})]
        // Paraphrase: "application/grpc-web" is outside this grammar.
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        SubProtocolResult result = select("application/grpc-web");

        assertThat(result.supported(), is(false));
    }

    @Test
    void testGrpcContentTypeWithProtoSuffixIsSelected() {
        // * **Content-Type** → "content-type" "application/grpc" [("+proto" / "+json" / {_custom_})]
        // Spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
        SubProtocolResult result = select("application/grpc+proto");

        assertThat(result.supported(), is(true));
        assertThat(result.subProtocol(), instanceOf(GrpcProtocolHandlerNotFound.class));
    }

    private static SubProtocolResult select(String contentType) {
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(HeaderNames.CONTENT_TYPE, contentType);

        return GrpcProtocolSelector.create(GrpcConfig.create())
                .subProtocol(null,
                             HttpPrologue.create("HTTP/2", "https", "2", Method.POST, "/StringService/Upper", false),
                             Http2Headers.create(headers),
                             null,
                             1,
                             null,
                             null,
                             null,
                             Http2StreamState.OPEN,
                             Router.empty());
    }
}
