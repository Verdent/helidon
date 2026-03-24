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

import java.util.function.Supplier;

import io.helidon.config.Config;
import io.helidon.config.ConfigBuilderSupport;
import io.helidon.service.registry.Service;
import io.helidon.webclient.grpc.GrpcClient;

@Service.Singleton
@Service.Named(ConfiguredGrpcClient.CLIENT_NAME)
class ConfiguredGrpcClient implements Supplier<GrpcClient> {
    static final String CLIENT_NAME = "configured-text-service";
    private static final String URI_EXPRESSION =
            "http://localhost:${test.server.socket." + ConfiguredTextServiceEndpoint.SOCKET_NAME + ".port}";

    private final Config config;
    private volatile GrpcClient client;

    @Service.Inject
    ConfiguredGrpcClient(Config config) {
        this.config = config;
    }

    @Override
    public GrpcClient get() {
        GrpcClient existing = client;
        if (existing != null) {
            return existing;
        }

        synchronized (this) {
            existing = client;
            if (existing == null) {
                String uri = ConfigBuilderSupport.resolveExpression(config, URI_EXPRESSION);
                existing = GrpcClient.create(it -> it
                        .baseUri(uri)
                        .tls(t -> t.enabled(false)));
                client = existing;
            }
        }

        return existing;
    }
}
