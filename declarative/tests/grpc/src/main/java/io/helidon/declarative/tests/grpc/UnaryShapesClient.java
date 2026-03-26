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

import java.util.Iterator;

import io.helidon.webclient.grpc.RpcClient;
import com.google.protobuf.Empty;

@RpcClient.Endpoint("${unary-shapes.client.uri:http://localhost:8080}")
@RpcClient.ServiceName(UnaryShapesEndpoint.SERVICE_NAME)
interface UnaryShapesClient {
    @RpcClient.Unary("DirectUpper")
    TextMessages.TextMessage directUpper(TextMessages.TextMessage request);

    @RpcClient.Unary("NoArgUpper")
    TextMessages.TextMessage noArgUpper();

    @RpcClient.Unary("ObserverUpper")
    TextMessages.TextMessage observerUpper();

    @RpcClient.Unary("Notify")
    Empty notify(TextMessages.TextMessage request);

    @RpcClient.Unary("Ping")
    Empty ping();

    @RpcClient.ServerStreaming("NoArgSplit")
    Iterator<TextMessages.TextMessage> noArgSplit();

    @RpcClient.ServerStreaming("ObserverSplit")
    Iterator<TextMessages.TextMessage> observerSplit();
}
