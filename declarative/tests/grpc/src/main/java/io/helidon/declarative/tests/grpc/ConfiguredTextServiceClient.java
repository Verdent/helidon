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

import io.helidon.webclient.grpc.RpcClient;

@RpcClient.Endpoint(value = ConfiguredTextServiceClient.INVALID_URI,
                    clientName = ConfiguredTextServiceClient.CLIENT_NAME)
@RpcClient.ServiceName(ConfiguredTextServiceClient.SERVICE_NAME_EXPRESSION)
interface ConfiguredTextServiceClient {
    String INVALID_URI = "http://localhost:1";
    String CLIENT_NAME = ConfiguredGrpcClient.CLIENT_NAME;
    String SERVICE_NAME_EXPRESSION =
            "${configured-text-service.grpc.service-name:" + ConfiguredTextServiceEndpoint.DEFAULT_SERVICE_NAME + "}";

    @RpcClient.Unary("Upper")
    TextMessages.TextMessage upper(TextMessages.TextMessage request);
}
