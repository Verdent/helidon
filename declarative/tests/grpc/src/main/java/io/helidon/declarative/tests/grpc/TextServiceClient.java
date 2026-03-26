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
import java.util.stream.Stream;

import io.helidon.webclient.grpc.RpcClient;

@RpcClient.Interceptors(TextServiceClientInterceptor.class)
@RpcClient.Endpoint("${text-service.client.uri:http://localhost:8080}")
@RpcClient.ServiceName(TextServiceGrpc.SERVICE_NAME)
interface TextServiceClient {
    @RpcClient.Unary("Upper")
    @RpcClient.Interceptors(TextServiceClientUpperInterceptor.class)
    TextMessages.TextMessage upper(TextMessages.TextMessage request);

    @RpcClient.ServerStreaming("Split")
    Stream<TextMessages.TextMessage> split(TextMessages.TextMessage request);

    @RpcClient.ClientStreaming("Join")
    TextMessages.TextMessage join(Stream<TextMessages.TextMessage> request);

    @RpcClient.Bidirectional("Echo")
    Iterator<TextMessages.TextMessage> echo(Iterator<TextMessages.TextMessage> request);
}
