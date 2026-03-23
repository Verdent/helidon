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

import io.helidon.grpc.api.RpcServer;
import io.helidon.service.registry.Service;

import com.google.protobuf.Descriptors;
import io.grpc.stub.StreamObserver;

@RpcServer.Endpoint
@RpcServer.Listener(ConfiguredStringServiceEndpoint.LISTENER_EXPRESSION)
@RpcServer.ServiceName(ConfiguredStringServiceEndpoint.SERVICE_NAME_EXPRESSION)
@Service.Singleton
class ConfiguredStringServiceEndpoint {
    static final String SOCKET_NAME = "grpc-config";
    static final String CONFIGURED_SERVICE_NAME = StringServiceGrpc.SERVICE_NAME;
    static final String DEFAULT_SERVICE_NAME = "grpc.declarative.DefaultConfiguredStringService";
    static final String LISTENER_EXPRESSION = "${configured-string-service.server.listener:@default}";
    static final String SERVICE_NAME_EXPRESSION =
            "${configured-string-service.grpc.service-name:" + DEFAULT_SERVICE_NAME + "}";

    @RpcServer.Proto
    Descriptors.FileDescriptor proto() {
        return Strings.getDescriptor();
    }

    @RpcServer.Unary("Upper")
    void upper(Strings.StringMessage request, StreamObserver<Strings.StringMessage> observer) {
        observer.onNext(Strings.StringMessage.newBuilder()
                                .setText("CONFIGURED:" + request.getText().toUpperCase(Locale.ROOT))
                                .build());
        observer.onCompleted();
    }
}
