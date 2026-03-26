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

package io.helidon.declarative.tests.grpc;

import java.util.Locale;

import io.helidon.webserver.grpc.RpcServer;

@RpcServer.Endpoint
@RpcServer.Listener("@default")
@RpcServer.ServiceName(UnaryShapesEndpoint.SERVICE_NAME)
class UnaryShapesEndpoint {
    static final String SERVICE_NAME = "grpc.declarative.UnaryShapes";

    @RpcServer.Unary("DirectUpper")
    TextMessages.TextMessage directUpper(TextMessages.TextMessage request) {
        return upper("DIRECT", request);
    }

    private static TextMessages.TextMessage upper(String prefix, TextMessages.TextMessage request) {
        return TextMessages.TextMessage.newBuilder()
                .setText(prefix + ":" + request.getText().toUpperCase(Locale.ROOT))
                .build();
    }
}
